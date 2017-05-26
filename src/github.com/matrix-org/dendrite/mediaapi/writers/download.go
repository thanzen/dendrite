// Copyright 2017 Vector Creations Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package writers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/mediaapi/config"
	"github.com/matrix-org/dendrite/mediaapi/fileutils"
	"github.com/matrix-org/dendrite/mediaapi/storage"
	"github.com/matrix-org/dendrite/mediaapi/types"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/util"
)

const mediaIDCharacters = "A-Za-z0-9_=-"

// Note: unfortunately regex.MustCompile() cannot be assigned to a const
var mediaIDRegex = regexp.MustCompile("[" + mediaIDCharacters + "]+")

// Error types used by downloadRequest.getMediaMetadata
// FIXME: make into types
var (
	errDBQuery    = fmt.Errorf("error querying database for media")
	errDBNotFound = fmt.Errorf("media not found")
)

// downloadRequest metadata included in or derivable from an download request
// https://matrix.org/docs/spec/client_server/r0.2.0.html#get-matrix-media-r0-download-servername-mediaid
type downloadRequest struct {
	MediaMetadata *types.MediaMetadata
	Logger        *log.Entry
}

// Download implements /download
// Files from this server (i.e. origin == cfg.ServerName) are served directly
// Files from remote servers (i.e. origin != cfg.ServerName) are cached locally.
// If they are present in the cache, they are served directly.
// If they are not present in the cache, they are obtained from the remote server and
// simultaneously served back to the client and written into the cache.
func Download(w http.ResponseWriter, req *http.Request, origin gomatrixserverlib.ServerName, mediaID types.MediaID, cfg *config.MediaAPI, db *storage.Database, activeRemoteRequests *types.ActiveRemoteRequests) {
	r := &downloadRequest{
		MediaMetadata: &types.MediaMetadata{
			MediaID: mediaID,
			Origin:  origin,
		},
		Logger: util.GetLogger(req.Context()),
	}

	// request validation
	if req.Method != "GET" {
		r.jsonErrorResponse(w, util.JSONResponse{
			Code: 405,
			JSON: jsonerror.Unknown("request method must be GET"),
		})
		return
	}

	if resErr := r.Validate(); resErr != nil {
		r.jsonErrorResponse(w, *resErr)
		return
	}

	if resErr := r.doDownload(w, cfg, db, activeRemoteRequests); resErr != nil {
		r.jsonErrorResponse(w, *resErr)
		return
	}
}

func (r *downloadRequest) jsonErrorResponse(w http.ResponseWriter, res util.JSONResponse) {
	// Marshal JSON response into raw bytes to send as the HTTP body
	resBytes, err := json.Marshal(res.JSON)
	if err != nil {
		r.Logger.WithError(err).Error("Failed to marshal JSONResponse")
		// this should never fail to be marshalled so drop err to the floor
		res = util.MessageResponse(500, "Internal Server Error")
		resBytes, _ = json.Marshal(res.JSON)
	}

	// Set status code and write the body
	w.WriteHeader(res.Code)
	r.Logger.WithField("code", res.Code).Infof("Responding (%d bytes)", len(resBytes))
	w.Write(resBytes)
}

// Validate validates the downloadRequest fields
func (r *downloadRequest) Validate() *util.JSONResponse {
	if mediaIDRegex.MatchString(string(r.MediaMetadata.MediaID)) == false {
		return &util.JSONResponse{
			Code: 404,
			JSON: jsonerror.NotFound(fmt.Sprintf("mediaId must be a non-empty string using only characters in %v", mediaIDCharacters)),
		}
	}
	// Note: the origin will be validated either by comparison to the configured server name of this homeserver
	// or by a DNS SRV record lookup when creating a request for remote files
	if r.MediaMetadata.Origin == "" {
		return &util.JSONResponse{
			Code: 404,
			JSON: jsonerror.NotFound("serverName must be a non-empty string"),
		}
	}
	return nil
}

func (r *downloadRequest) doDownload(w http.ResponseWriter, cfg *config.MediaAPI, db *storage.Database, activeRemoteRequests *types.ActiveRemoteRequests) *util.JSONResponse {
	// check if we have a record of the media in our database
	mediaMetadata, err := r.getMediaMetadata(db)
	if err == nil {
		// If we have a record, we can respond from the local file
		r.MediaMetadata = mediaMetadata
		return r.respondFromLocalFile(w, cfg.AbsBasePath)
	} else if err == errDBNotFound {
		if r.MediaMetadata.Origin == cfg.ServerName {
			// If we do not have a record and the origin is local, the file is not found
			r.Logger.WithError(err).Warn("Failed to look up file in database")
			return &util.JSONResponse{
				Code: 404,
				JSON: jsonerror.NotFound(fmt.Sprintf("File with media ID %q does not exist", r.MediaMetadata.MediaID)),
			}
		}
		// If we do not have a record and the origin is remote, we need to fetch it and respond with that file
		return r.respondFromRemoteFile(w, cfg, db, activeRemoteRequests)
	}
	// Another error from the database
	r.Logger.WithError(err).WithFields(log.Fields{
		"MediaID": r.MediaMetadata.MediaID,
		"Origin":  r.MediaMetadata.Origin,
	}).Error("Error querying the database.")
	return &util.JSONResponse{
		Code: 500,
		JSON: jsonerror.Unknown("Internal server error"),
	}
}

// getMediaMetadata queries the database for media metadata
func (r *downloadRequest) getMediaMetadata(db *storage.Database) (*types.MediaMetadata, error) {
	mediaMetadata, err := db.GetMediaMetadata(r.MediaMetadata.MediaID, r.MediaMetadata.Origin)
	if err != nil {
		if err == sql.ErrNoRows {
			r.Logger.WithFields(log.Fields{
				"Origin":  r.MediaMetadata.Origin,
				"MediaID": r.MediaMetadata.MediaID,
			}).Info("Media not found in database.")
			return nil, errDBNotFound
		}
		r.Logger.WithError(err).WithFields(log.Fields{
			"Origin":  r.MediaMetadata.Origin,
			"MediaID": r.MediaMetadata.MediaID,
		}).Error("Error querying database for media.")
		return nil, errDBQuery
	}
	return mediaMetadata, nil
}

// respondFromLocalFile reads a file from local storage and writes it to the http.ResponseWriter
// Returns a util.JSONResponse error in case of error
func (r *downloadRequest) respondFromLocalFile(w http.ResponseWriter, absBasePath types.Path) *util.JSONResponse {
	r.Logger.WithFields(log.Fields{
		"MediaID":             r.MediaMetadata.MediaID,
		"Origin":              r.MediaMetadata.Origin,
		"UploadName":          r.MediaMetadata.UploadName,
		"Base64Hash":          r.MediaMetadata.Base64Hash,
		"FileSizeBytes":       r.MediaMetadata.FileSizeBytes,
		"Content-Type":        r.MediaMetadata.ContentType,
		"Content-Disposition": r.MediaMetadata.ContentDisposition,
	}).Info("Responding with file")

	filePath, err := fileutils.GetPathFromBase64Hash(r.MediaMetadata.Base64Hash, absBasePath)
	if err != nil {
		// FIXME: Remove erroneous file from database?
		r.Logger.WithError(err).Warn("Failed to get file path from metadata")
		return &util.JSONResponse{
			Code: 404,
			JSON: jsonerror.NotFound(fmt.Sprintf("File with media ID %q does not exist", r.MediaMetadata.MediaID)),
		}
	}
	file, err := os.Open(filePath)
	if err != nil {
		// FIXME: Remove erroneous file from database?
		r.Logger.WithError(err).Warn("Failed to open file")
		return &util.JSONResponse{
			Code: 404,
			JSON: jsonerror.NotFound(fmt.Sprintf("File with media ID %q does not exist", r.MediaMetadata.MediaID)),
		}
	}

	stat, err := file.Stat()
	if err != nil {
		// FIXME: Remove erroneous file from database?
		r.Logger.WithError(err).Warn("Failed to stat file")
		return &util.JSONResponse{
			Code: 404,
			JSON: jsonerror.NotFound(fmt.Sprintf("File with media ID %q does not exist", r.MediaMetadata.MediaID)),
		}
	}

	if r.MediaMetadata.FileSizeBytes > 0 && int64(r.MediaMetadata.FileSizeBytes) != stat.Size() {
		r.Logger.WithFields(log.Fields{
			"fileSizeDatabase": r.MediaMetadata.FileSizeBytes,
			"fileSizeDisk":     stat.Size(),
		}).Warn("File size in database and on-disk differ.")
		// FIXME: Remove erroneous file from database?
	}

	w.Header().Set("Content-Type", string(r.MediaMetadata.ContentType))
	w.Header().Set("Content-Length", strconv.FormatInt(int64(r.MediaMetadata.FileSizeBytes), 10))
	contentSecurityPolicy := "default-src 'none';" +
		" script-src 'none';" +
		" plugin-types application/pdf;" +
		" style-src 'unsafe-inline';" +
		" object-src 'self';"
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)

	if bytesResponded, err := io.Copy(w, file); err != nil {
		r.Logger.WithError(err).Warn("Failed to copy from cache")
		if bytesResponded == 0 {
			return &util.JSONResponse{
				Code: 500,
				JSON: jsonerror.NotFound(fmt.Sprintf("Failed to respond with file with media ID %q", r.MediaMetadata.MediaID)),
			}
		}
		// If we have written any data then we have already responded with 200 OK and all we can do is close the connection
		// FIXME: close the connection here or just return?
		r.closeConnection(w)
	}
	return nil
}

func (r *downloadRequest) closeConnection(w http.ResponseWriter) {
	r.Logger.WithFields(log.Fields{
		"Origin":  r.MediaMetadata.Origin,
		"MediaID": r.MediaMetadata.MediaID,
	}).Info("Attempting to close the connection.")
	hijacker, ok := w.(http.Hijacker)
	if ok {
		connection, _, hijackErr := hijacker.Hijack()
		if hijackErr == nil {
			r.Logger.WithFields(log.Fields{
				"Origin":  r.MediaMetadata.Origin,
				"MediaID": r.MediaMetadata.MediaID,
			}).Info("Closing")
			connection.Close()
		} else {
			r.Logger.WithError(hijackErr).WithFields(log.Fields{
				"Origin":  r.MediaMetadata.Origin,
				"MediaID": r.MediaMetadata.MediaID,
			}).Warn("Error trying to hijack and close connection")
		}
	}
}

// respondFromRemoteFile fetches the remote file, caches it locally and responds from that local file
// A hash map of active remote requests to sync.Cond is used to only download remote files once,
// regardless of how many download requests are received.
// Returns a util.JSONResponse error in case of error
func (r *downloadRequest) respondFromRemoteFile(w http.ResponseWriter, cfg *config.MediaAPI, db *storage.Database, activeRemoteRequests *types.ActiveRemoteRequests) *util.JSONResponse {
	// FIXME: NOTE LOCKING
	mediaMetadata, resErr := r.getMediaMetadataForRemoteFile(db, activeRemoteRequests)
	if resErr != nil {
		return resErr
	} else if mediaMetadata != nil {
		// If we have a record, we can respond from the local file
		r.MediaMetadata = mediaMetadata
	} else {
		// If we have a record, we can respond from the local file
		// FIXME: NOTE LOCKING
		if resErr := r.getRemoteFile(cfg.AbsBasePath, cfg.MaxFileSizeBytes, db, activeRemoteRequests); resErr != nil {
			return resErr
		}
	}
	return r.respondFromLocalFile(w, cfg.AbsBasePath)
}

func (r *downloadRequest) getMediaMetadataForRemoteFile(db *storage.Database, activeRemoteRequests *types.ActiveRemoteRequests) (*types.MediaMetadata, *util.JSONResponse) {
	activeRemoteRequests.Lock()
	defer activeRemoteRequests.Unlock()

	mediaMetadata, err := r.getMediaMetadata(db)
	if err == nil {
		// If we have a record, we can respond from the local file
		return mediaMetadata, nil
	} else if err == errDBQuery {
		resErr := jsonerror.InternalServerError()
		return nil, &resErr
	}
	// No record was found

	// Check if there is an active remote request for the file
	mxcURL := "mxc://" + string(r.MediaMetadata.Origin) + "/" + string(r.MediaMetadata.MediaID)
	if activeRemoteRequestCondition, ok := activeRemoteRequests.MXCToCond[mxcURL]; ok {
		r.Logger.WithFields(log.Fields{
			"Origin":  r.MediaMetadata.Origin,
			"MediaID": r.MediaMetadata.MediaID,
		}).Info("Waiting for another goroutine to fetch the remote file.")

		activeRemoteRequestCondition.Wait()
		activeRemoteRequests.Unlock()
		// NOTE: there is still a deferred Unlock() that will unlock this
		activeRemoteRequests.Lock()

		mediaMetadata, err := r.getMediaMetadata(db)
		if err == nil {
			r.Logger.WithFields(log.Fields{
				"Origin":  r.MediaMetadata.Origin,
				"MediaID": r.MediaMetadata.MediaID,
			}).Info("Other goroutine fetched the remote file.")
			return mediaMetadata, nil
		}

		r.Logger.WithFields(log.Fields{
			"Origin":  r.MediaMetadata.Origin,
			"MediaID": r.MediaMetadata.MediaID,
		}).Warn("Other goroutine failed to fetch the remote file.")

		if err == errDBNotFound {
			return nil, &util.JSONResponse{
				Code: 404,
				JSON: jsonerror.NotFound("File not found."),
			}
		}
		resErr := jsonerror.InternalServerError()
		return nil, &resErr
	}

	// No active remote request so create one
	activeRemoteRequests.MXCToCond[mxcURL] = &sync.Cond{L: activeRemoteRequests}
	return nil, nil
}

// getRemoteFile fetches the file from the remote server and stores its metadata in the database
// Only the owner of the activeRemoteRequestCondition for this origin and media ID should call this function.
func (r *downloadRequest) getRemoteFile(absBasePath types.Path, maxFileSizeBytes types.FileSizeBytes, db *storage.Database, activeRemoteRequests *types.ActiveRemoteRequests) *util.JSONResponse {
	// Wake up other goroutines after this function returns.
	isError := true
	defer func() {
		if isError {
			// If an error happens, the lock MUST NOT have been taken, isError MUST be true and so the lock is taken here.
			activeRemoteRequests.Lock()
		}
		defer activeRemoteRequests.Unlock()
		mxcURL := "mxc://" + string(r.MediaMetadata.Origin) + "/" + string(r.MediaMetadata.MediaID)
		if activeRemoteRequestCondition, ok := activeRemoteRequests.MXCToCond[mxcURL]; ok {
			r.Logger.WithFields(log.Fields{
				"Origin":  r.MediaMetadata.Origin,
				"MediaID": r.MediaMetadata.MediaID,
			}).Info("Signalling other goroutines waiting for this goroutine to fetch the file.")
			activeRemoteRequestCondition.Broadcast()
		}
		delete(activeRemoteRequests.MXCToCond, mxcURL)
	}()

	finalPath, duplicate, resErr := r.fetchRemoteFile(absBasePath, maxFileSizeBytes)
	if resErr != nil {
		return resErr
	}

	// NOTE: Writing the metadata to the media repository database and removing the mxcURL from activeRemoteRequests needs to be atomic.
	// If it were not atomic, a new request for the same file could come in in routine A and check the database before the INSERT.
	// Routine B which was fetching could then have its INSERT complete and remove the mxcURL from the activeRemoteRequests.
	// If routine A then checked the activeRemoteRequests it would think it needed to fetch the file when it's already in the database.
	// The locking below mitigates this situation.

	// NOTE: The following two lines MUST remain together!
	// isError == true causes the lock to be taken in a deferred function!
	activeRemoteRequests.Lock()
	isError = false

	r.Logger.WithFields(log.Fields{
		"MediaID":             r.MediaMetadata.MediaID,
		"Origin":              r.MediaMetadata.Origin,
		"Base64Hash":          r.MediaMetadata.Base64Hash,
		"UploadName":          r.MediaMetadata.UploadName,
		"FileSizeBytes":       r.MediaMetadata.FileSizeBytes,
		"Content-Type":        r.MediaMetadata.ContentType,
		"Content-Disposition": r.MediaMetadata.ContentDisposition,
	}).Info("Storing file metadata to media repository database")

	// FIXME: timeout db request
	if err := db.StoreMediaMetadata(r.MediaMetadata); err != nil {
		// If the file is a duplicate (has the same hash as an existing file) then
		// there is valid metadata in the database for that file. As such we only
		// remove the file if it is not a duplicate.
		if duplicate == false {
			finalDir := path.Dir(string(finalPath))
			fileutils.RemoveDir(types.Path(finalDir), r.Logger)
		}
		// NOTE: It should really not be possible to fail the uniqueness test here so
		// there is no need to handle that separately
		return &util.JSONResponse{
			Code: 500,
			JSON: jsonerror.InternalServerError(),
		}
	}

	// TODO: generate thumbnails

	r.Logger.WithFields(log.Fields{
		"MediaID":             r.MediaMetadata.MediaID,
		"Origin":              r.MediaMetadata.Origin,
		"UploadName":          r.MediaMetadata.UploadName,
		"Base64Hash":          r.MediaMetadata.Base64Hash,
		"FileSizeBytes":       r.MediaMetadata.FileSizeBytes,
		"Content-Type":        r.MediaMetadata.ContentType,
		"Content-Disposition": r.MediaMetadata.ContentDisposition,
	}).Infof("Remote file cached")

	return nil
}

func (r *downloadRequest) fetchRemoteFile(absBasePath types.Path, maxFileSizeBytes types.FileSizeBytes) (types.Path, bool, *util.JSONResponse) {
	r.Logger.WithFields(log.Fields{
		"Origin":  r.MediaMetadata.Origin,
		"MediaID": r.MediaMetadata.MediaID,
	}).Info("Fetching remote file")

	// create request for remote file
	resp, resErr := r.createRemoteRequest()
	if resErr != nil {
		return "", false, resErr
	}
	defer resp.Body.Close()

	// get metadata from request and set metadata on response
	contentLength, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		r.Logger.WithError(err).Warn("Failed to parse content length")
	}
	r.MediaMetadata.FileSizeBytes = types.FileSizeBytes(contentLength)
	r.MediaMetadata.ContentType = types.ContentType(resp.Header.Get("Content-Type"))
	r.MediaMetadata.ContentDisposition = types.ContentDisposition(resp.Header.Get("Content-Disposition"))
	// FIXME: parse from Content-Disposition header if possible, else fall back
	//r.MediaMetadata.UploadName          = types.Filename()

	r.Logger.WithFields(log.Fields{
		"MediaID": r.MediaMetadata.MediaID,
		"Origin":  r.MediaMetadata.Origin,
	}).Info("Transferring remote file")

	// The file data is hashed but is NOT used as the MediaID, unlike in Upload. The hash is useful as a
	// method of deduplicating files to save storage, as well as a way to conduct
	// integrity checks on the file data in the repository.
	hash, bytesWritten, tmpDir, copyError := fileutils.WriteTempFile(resp.Body, maxFileSizeBytes, absBasePath)
	if copyError != nil {
		logFields := log.Fields{
			"MediaID": r.MediaMetadata.MediaID,
			"Origin":  r.MediaMetadata.Origin,
		}
		if copyError == fileutils.ErrFileIsTooLarge {
			logFields["MaxFileSizeBytes"] = maxFileSizeBytes
		}
		r.Logger.WithError(copyError).WithFields(logFields).Warn("Error while downloading file from remote server")
		fileutils.RemoveDir(tmpDir, r.Logger)
		return "", false, &util.JSONResponse{
			Code: 502,
			JSON: jsonerror.Unknown(fmt.Sprintf("File could not be downloaded from remote server")),
		}
	}

	r.Logger.WithFields(log.Fields{
		"MediaID": r.MediaMetadata.MediaID,
		"Origin":  r.MediaMetadata.Origin,
	}).Info("Remote file transferred")

	// It's possible the bytesWritten to the temporary file is different to the reported Content-Length from the remote
	// request's response. bytesWritten is therefore used as it is what would be sent to clients when reading from the local
	// file.
	r.MediaMetadata.FileSizeBytes = types.FileSizeBytes(bytesWritten)
	r.MediaMetadata.Base64Hash = hash
	// r.MediaMetadata.UserID = types.MatrixUserID("@:" + string(r.MediaMetadata.Origin))

	// The database is the source of truth so we need to have moved the file first
	finalPath, duplicate, err := fileutils.MoveFileWithHashCheck(tmpDir, r.MediaMetadata, absBasePath, r.Logger)
	if err != nil {
		r.Logger.WithError(err).Error("Failed to move file.")
		return "", false, &util.JSONResponse{
			Code: 500,
			JSON: jsonerror.InternalServerError(),
		}
	}
	if duplicate {
		r.Logger.WithField("dst", finalPath).Info("File was stored previously - discarding duplicate")
		// Continue on to store the metadata in the database
	}

	return types.Path(finalPath), duplicate, nil
}

func (r *downloadRequest) createRemoteRequest() (*http.Response, *util.JSONResponse) {
	urls := getMatrixURLs(r.MediaMetadata.Origin)

	r.Logger.WithField("URL", urls[0]).Info("Connecting to remote")

	remoteReqAddr := urls[0] + "/_matrix/media/v1/download/" + string(r.MediaMetadata.Origin) + "/" + string(r.MediaMetadata.MediaID)
	remoteReq, err := http.NewRequest("GET", remoteReqAddr, nil)
	if err != nil {
		return nil, &util.JSONResponse{
			Code: 500,
			JSON: jsonerror.Unknown(fmt.Sprintf("File with media ID %q could not be downloaded from %q", r.MediaMetadata.MediaID, r.MediaMetadata.Origin)),
		}
	}

	remoteReq.Header.Set("Host", string(r.MediaMetadata.Origin))

	client := http.Client{}
	resp, err := client.Do(remoteReq)
	if err != nil {
		return nil, &util.JSONResponse{
			Code: 502,
			JSON: jsonerror.Unknown(fmt.Sprintf("File with media ID %q could not be downloaded from %q", r.MediaMetadata.MediaID, r.MediaMetadata.Origin)),
		}
	}

	if resp.StatusCode != 200 {
		r.Logger.WithFields(log.Fields{
			"Origin":     r.MediaMetadata.Origin,
			"MediaID":    r.MediaMetadata.MediaID,
			"StatusCode": resp.StatusCode,
		}).Info("Received error response")
		if resp.StatusCode == 404 {
			r.Logger.WithFields(log.Fields{
				"Origin":     r.MediaMetadata.Origin,
				"MediaID":    r.MediaMetadata.MediaID,
				"StatusCode": resp.StatusCode,
			}).Warn("Remote server says file does not exist")
			return nil, &util.JSONResponse{
				Code: 404,
				JSON: jsonerror.NotFound(fmt.Sprintf("File with media ID %q does not exist", r.MediaMetadata.MediaID)),
			}
		}
		return nil, &util.JSONResponse{
			Code: 502,
			JSON: jsonerror.Unknown(fmt.Sprintf("File with media ID %q could not be downloaded from %q", r.MediaMetadata.MediaID, r.MediaMetadata.Origin)),
		}
	}

	return resp, nil
}

// getMatrixURLs attempts to discover URLs to contact the homeserver
func getMatrixURLs(serverName gomatrixserverlib.ServerName) []string {
	_, srvs, err := net.LookupSRV("matrix", "tcp", string(serverName))
	if err != nil {
		return []string{"https://" + string(serverName) + ":8448"}
	}

	results := make([]string, 0, len(srvs))
	for _, srv := range srvs {
		if srv == nil {
			continue
		}

		url := []string{"https://", strings.Trim(srv.Target, "."), ":", strconv.Itoa(int(srv.Port))}
		results = append(results, strings.Join(url, ""))
	}

	// TODO: Order based on priority and weight.

	return results
}

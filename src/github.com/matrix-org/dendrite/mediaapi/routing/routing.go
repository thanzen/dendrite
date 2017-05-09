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

package routing

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/matrix-org/dendrite/mediaapi/config"
	"github.com/matrix-org/dendrite/mediaapi/storage"
	"github.com/matrix-org/dendrite/mediaapi/types"
	"github.com/matrix-org/dendrite/mediaapi/writers"
	"github.com/matrix-org/util"
	"github.com/prometheus/client_golang/prometheus"
)

const pathPrefixR0 = "/_matrix/media/v1"

// Setup registers HTTP handlers with the given ServeMux. It also supplies the given http.Client
// to clients which need to make outbound HTTP requests.
func Setup(servMux *http.ServeMux, httpClient *http.Client, cfg config.MediaAPI, db *storage.Database) {
	apiMux := mux.NewRouter()
	r0mux := apiMux.PathPrefix(pathPrefixR0).Subrouter()
	r0mux.Handle("/upload", make("upload", util.NewJSONRequestHandler(func(req *http.Request) util.JSONResponse {
		return writers.Upload(req, cfg, db)
	})))

	r0mux.Handle("/download/{serverName}/{mediaId}",
		prometheus.InstrumentHandler("download", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			util.SetupRequestLogging(req)

			// Set common headers returned regardless of the outcome of the request
			util.SetCORSHeaders(w)
			// TODO: fix comment
			w.Header().Set("Content-Type", "application/json")

			vars := mux.Vars(req)
			writers.Download(w, req, types.ServerName(vars["serverName"]), types.MediaID(vars["mediaId"]), cfg, db)
		})),
	)

	servMux.Handle("/metrics", prometheus.Handler())
	servMux.Handle("/api/", http.StripPrefix("/api", apiMux))
}

// make a util.JSONRequestHandler into an http.Handler
func make(metricsName string, h util.JSONRequestHandler) http.Handler {
	return prometheus.InstrumentHandler(metricsName, util.MakeJSONAPI(h))
}

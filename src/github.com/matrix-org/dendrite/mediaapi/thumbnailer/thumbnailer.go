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

package thumbnailer

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/matrix-org/dendrite/mediaapi/types"
	"gopkg.in/h2non/bimg.v1"
)

// thumbnailTemplate is the filename template for thumbnails
const thumbnailTemplate = "thumbnail-%vx%v-%v"

// GenerateThumbnails generates the configured thumbnail sizes for the source file
func GenerateThumbnails(src types.Path, configs []types.ThumbnailSize, activeThumbnailGeneration *types.ActiveThumbnailGeneration, logger *log.Entry) error {
	buffer, err := bimg.Read(string(src))
	if err != nil {
		logger.WithError(err).WithField("src", src).Error("Failed to read src file")
		return err
	}
	for _, config := range configs {
		// Note: createThumbnail does locking based on activeThumbnailGeneration
		if err = createThumbnail(src, buffer, config, activeThumbnailGeneration, logger); err != nil {
			logger.WithError(err).WithField("src", src).Error("Failed to generate thumbnails")
			return err
		}
	}
	return nil
}

// GenerateThumbnail generates the configured thumbnail size for the source file
func GenerateThumbnail(src types.Path, config types.ThumbnailSize, activeThumbnailGeneration *types.ActiveThumbnailGeneration, logger *log.Entry) error {
	buffer, err := bimg.Read(string(src))
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"src": src,
		}).Error("Failed to read src file")
		return err
	}
	// Note: createThumbnail does locking based on activeThumbnailGeneration
	if err = createThumbnail(src, buffer, config, activeThumbnailGeneration, logger); err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"src": src,
		}).Error("Failed to generate thumbnails")
		return err
	}
	return nil
}

// GetThumbnailPath returns the path to a thumbnail given the absolute src path and thumbnail size configuration
func GetThumbnailPath(src types.Path, config types.ThumbnailSize) types.Path {
	srcDir := filepath.Dir(string(src))
	return types.Path(filepath.Join(
		srcDir,
		fmt.Sprintf(thumbnailTemplate, config.Width, config.Height, config.ResizeMethod),
	))
}

// createThumbnail checks if the thumbnail exists, and if not, generates it
// Thumbnail generation is only done once for each non-existing thumbnail.
func createThumbnail(src types.Path, buffer []byte, config types.ThumbnailSize, activeThumbnailGeneration *types.ActiveThumbnailGeneration, logger *log.Entry) (errorReturn error) {
	dst := GetThumbnailPath(src, config)

	// Note: getActiveThumbnailGeneration uses mutexes and conditions from activeThumbnailGeneration
	isActive, err := getActiveThumbnailGeneration(dst, config, activeThumbnailGeneration, logger)
	if err != nil {
		return err
	}

	if isActive {
		// Note: This is an active request that MUST broadcastGeneration to wake up waiting goroutines!
		// Note: broadcastGeneration uses mutexes and conditions from activeThumbnailGeneration
		defer func() {
			// Note: errorReturn is the named return variable so we wrap this in a closure to re-evaluate the arguments at defer-time
			broadcastGeneration(dst, activeThumbnailGeneration, config, errorReturn, logger)
		}()
	}

	// Check if the thumbnail exists.
	// Note: The double-negative is intentional as os.IsExist(err) != !os.IsNotExist(err).
	// The functions are error checkers to be used in different cases.
	if _, err = os.Stat(string(dst)); !os.IsNotExist(err) {
		// Thumbnail exists
		return nil
	}
	if isActive == false {
		// Note: This should not happen, but we check just in case.
		return fmt.Errorf("Not active thumbnail generator. Stat error: %q", err)
	}

	logger.WithFields(log.Fields{
		"Width":        config.Width,
		"Height":       config.Height,
		"ResizeMethod": config.ResizeMethod,
	}).Info("Generating thumbnail")
	start := time.Now()
	if err := resize(dst, buffer, config.Width, config.Height, config.ResizeMethod == "crop", logger); err != nil {
		return err
	}
	logger.WithFields(log.Fields{
		"Width":        config.Width,
		"Height":       config.Height,
		"ResizeMethod": config.ResizeMethod,
		"processTime":  time.Now().Sub(start),
	}).Info("Generated thumbnail")
	return nil
}

// getActiveThumbnailGeneration checks for active thumbnail generation
func getActiveThumbnailGeneration(dst types.Path, config types.ThumbnailSize, activeThumbnailGeneration *types.ActiveThumbnailGeneration, logger *log.Entry) (bool, error) {
	// Check if there is active thumbnail generation.
	activeThumbnailGeneration.Lock()
	defer activeThumbnailGeneration.Unlock()
	if activeThumbnailGenerationResult, ok := activeThumbnailGeneration.PathToResult[string(dst)]; ok {
		logger.WithFields(log.Fields{
			"Width":        config.Width,
			"Height":       config.Height,
			"ResizeMethod": config.ResizeMethod,
		}).Info("Waiting for another goroutine to generate the thumbnail.")

		// NOTE: Wait unlocks and locks again internally. There is still a deferred Unlock() that will unlock this.
		activeThumbnailGenerationResult.Cond.Wait()
		// Note: either there is an error or it is nil, either way returning it is correct
		return false, activeThumbnailGenerationResult.Err
	}

	// No active thumbnail generation so create one
	activeThumbnailGeneration.PathToResult[string(dst)] = &types.ThumbnailGenerationResult{
		Cond: &sync.Cond{L: activeThumbnailGeneration},
	}

	return true, nil
}

// broadcastGeneration broadcasts that thumbnail generation completed and the error to all waiting goroutines
// Note: This should only be called by the owner of the activeThumbnailGenerationResult
func broadcastGeneration(dst types.Path, activeThumbnailGeneration *types.ActiveThumbnailGeneration, config types.ThumbnailSize, errorReturn error, logger *log.Entry) {
	activeThumbnailGeneration.Lock()
	defer activeThumbnailGeneration.Unlock()
	if activeThumbnailGenerationResult, ok := activeThumbnailGeneration.PathToResult[string(dst)]; ok {
		logger.WithFields(log.Fields{
			"Width":        config.Width,
			"Height":       config.Height,
			"ResizeMethod": config.ResizeMethod,
		}).Info("Signalling other goroutines waiting for this goroutine to generate the thumbnail.")
		// Note: retErr is a named return value error that is signalled from here to waiting goroutines
		activeThumbnailGenerationResult.Err = errorReturn
		activeThumbnailGenerationResult.Cond.Broadcast()
	}
	delete(activeThumbnailGeneration.PathToResult, string(dst))
}

// resize scales an image to fit within the provided width and height
// If the source aspect ratio is different to the target dimensions, one edge will be smaller than requested
// If crop is set to true, the image will be scaled to fill the width and height with any excess being cropped off
func resize(dst types.Path, buffer []byte, w, h int, crop bool, logger *log.Entry) error {
	inImage := bimg.NewImage(buffer)

	inSize, err := inImage.Size()
	if err != nil {
		return err
	}

	options := bimg.Options{
		Type:    bimg.JPEG,
		Quality: 85,
	}
	if crop {
		options.Width = w
		options.Height = h
		options.Crop = true
	} else {
		inAR := float64(inSize.Width) / float64(inSize.Height)
		outAR := float64(w) / float64(h)

		if inAR > outAR {
			// input has wider AR than requested output so use requested width and calculate height to match input AR
			options.Width = w
			options.Height = int(float64(w) / inAR)
		} else {
			// input has narrower AR than requested output so use requested height and calculate width to match input AR
			options.Width = int(float64(h) * inAR)
			options.Height = h
		}
	}

	newImage, err := inImage.Process(options)
	if err != nil {
		return err
	}

	if err = bimg.Write(string(dst), newImage); err != nil {
		logger.WithError(err).Error("Failed to resize image")
	}

	return err
}

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
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/matrix-org/dendrite/mediaapi/types"
	"gopkg.in/h2non/bimg.v1"
)

// thumbnailTemplate is the filename template for thumbnails
const thumbnailTemplate = "thumbnail-%vx%v-%v"

// GenerateThumbnails generates the configured thumbnail sizes for the source file
func GenerateThumbnails(src types.Path, configs []types.ThumbnailSize, logger *log.Entry) error {
	start := time.Now().UnixNano()
	buffer, err := bimg.Read(string(src))
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"src": src,
		}).Error("Failed to read src file")
		return err
	}
	for _, config := range configs {
		if err = createThumbnail(src, buffer, config, logger); err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"src": src,
			}).Error("Failed to generate thumbnails")
			return err
		}
	}
	logger.WithFields(log.Fields{
		"src":           src,
		"processTimeNs": time.Now().UnixNano() - start,
	}).Info("Generated thumbnails")
	return nil
}

// GenerateThumbnail generates the configured thumbnail size for the source file
func GenerateThumbnail(src types.Path, config types.ThumbnailSize, logger *log.Entry) error {
	start := time.Now().UnixNano()
	buffer, err := bimg.Read(string(src))
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"src": src,
		}).Error("Failed to read src file")
		return err
	}
	if err = createThumbnail(src, buffer, config, logger); err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"src": src,
		}).Error("Failed to generate thumbnails")
		return err
	}
	logger.WithFields(log.Fields{
		"src":           src,
		"processTimeNs": time.Now().UnixNano() - start,
	}).Info("Generated thumbnail")
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

func createThumbnail(src types.Path, buffer []byte, config types.ThumbnailSize, logger *log.Entry) error {
	dst := GetThumbnailPath(src, config)
	// Note: The double-negative is intentional as os.IsExist(err) != !os.IsNotExist(err).
	// The functions are error checkers to be used in different cases.
	if _, err := os.Stat(string(dst)); !os.IsNotExist(err) {
		logger.WithField("dst", dst).Info("Thumbnail exists")
		return nil
	}
	if err := resize(dst, buffer, config.Width, config.Height, config.ResizeMethod == "crop", logger); err != nil {
		return err
	}
	return nil
}

// resize scales an image to fit within the provided width and height
// If the source aspect ratio is different to the target dimensions, one edge will be smaller than requested
// If crop is set to true, the image will be scaled to fill the width and height with any excess being cropped off
func resize(dst types.Path, buffer []byte, w, h int, crop bool, logger *log.Entry) error {
	cp := make([]byte, len(buffer), cap(buffer))
	copy(cp, buffer)
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

	if len(buffer) != len(cp) {
		logger.Panic("lengths differ!")
	}
	for i := 0; i < len(cp); i++ {
		if buffer[i] != cp[i] {
			logger.Panicf("buffer[%v] != cp[%v]", i, i)
		}
	}

	return err
}

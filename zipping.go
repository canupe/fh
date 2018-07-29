// fh project zipping.go
package main

import (
	"archive/zip"
	"io"
	"log"
	"os"
	"path/filepath"
)

// zipFilesAndCheck wraps zipFiles and check the created files, returning its size
func zipFilesAndCheck(fiin []string, fnout string) (uint32, error) {
	// call the wrapped function
	err := zipFiles(fiin, fnout)
	// test error
	if err != nil {
		return 0, err
	}
	// "test" the created file to be ok.
	// Actually what we really need is its size, to create a proper header for the output file
	fi, err := os.Stat(fnout)
	// if something wrong log and exit
	if err != nil {
		return 0, err
	}
	// return size and no error
	return uint32(fi.Size()), nil
}

// zipFiles takes a list of files in input, and adds all of them to a zip file
// whose name will be the fnout parameter string
func zipFiles(fiin []string, fnout string) error {
	// crete the file
	newfile, err := os.Create(fnout)
	// return if error happens
	if err != nil {
		return err
	}
	// defer the closing
	defer newfile.Close()

	// create a zip writer around the newfile writer
	zipWriter := zip.NewWriter(newfile)
	// defer the closing
	defer zipWriter.Close()
	// I tried this but the results are often worse than the default, so let it be default
	/*
		zipWriter.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
			return flate.NewWriter(w, flate.BestCompression)
		})
	*/
	// for each file
	for _, file := range fiin {
		// add it to the zipper
		err := addFileToZipWriter(file, zipWriter)
		if err != nil {
			// on error, log the name and return the error
			log.Println("Error adding", file)
			return err
		}

	}
	return nil
}

// addFileToZipWriter adds a file by its name to a zipwriter, and closes the file
func addFileToZipWriter(file string, zipWriter *zip.Writer) error {
	// basic printing
	log.Println("Adding", file, "to temporary archive")
	// open the file
	zipfile, err := os.Open(file)
	// on error, print file name and return the error
	if err != nil {
		log.Println("Cannot open", file)
		return err
	}
	// defer the closing
	defer zipfile.Close()
	// need a 'stat' because we must pass it to the zipWriter
	info, err := zipfile.Stat()
	// on error, print file name and return the error
	if err != nil {
		log.Println("Cannot stat", file)
		return err
	}
	// create a file header in zip for the new file
	header, err := zip.FileInfoHeader(info)
	// on error, print the file causing the problem and return the error
	if err != nil {
		log.Println("Cannot create file header", file)
		return err
	}
	// set the Deflate mode to have compression and not just storing
	header.Method = zip.Deflate
	// set the header in the zipWriter for this file
	writer, err := zipWriter.CreateHeader(header)
	// on error, print the file causing the problem and return the error
	if err != nil {
		log.Println("Cannot create header", file)
		return err
	}
	// now copy the file content into the writer
	n, err := io.Copy(writer, zipfile)
	// on error, print the file causing the problem and return the error
	if err != nil {
		log.Println("Cannot copy in zip", file)
		return err
	}
	// a final printing
	log.Println(file, ":", n, "bytes written")
	// return no error
	return nil
}

// unzipFile unzips the file named in filenameToUnzip in the folder
// named by the destination parameter
// return the list of the unzipped filenames
func unzipFile(filenameToUnzip string, destination string) ([]string, error) {
	// declare the array to return
	var filenames []string
	// open the zip reader above the file in input
	r, err := zip.OpenReader(filenameToUnzip)
	// return an error and the (empty) list
	if err != nil {
		return filenames, err
	}
	// defer the closing
	defer r.Close()

	// cycle on the files contained in the zip
	// for each file...
	for _, f := range r.File {
		// open it
		rc, err := f.Open()
		// if something goes wrong, return an error and the list so far
		if err != nil {
			return filenames, err
		}
		// defer the closing of the entry
		defer rc.Close()

		// Store filename/path for returning and using later on
		// join the path and the filename
		fpath := filepath.Join(destination, f.Name)
		// if it is a directory
		if f.FileInfo().IsDir() {
			// append to result
			filenames = append(filenames, fpath)
			// and make folder
			os.MkdirAll(fpath, os.ModePerm)
		} else {
			// if not a directory
			// append a .r to extracted file, to aovid
			// overwriting the original
			filenames = append(filenames, fpath+".r")
			// create all the necessary folders above
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				// on error, return filelist so far and the error
				return filenames, err
			}
			// create the output file for the extracted content
			outFile, err := os.OpenFile(fpath+".r", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			// on error, return filelist so far and the error
			if err != nil {
				return filenames, err
			}
			// copy the content in the newly generated files
			_, err = io.Copy(outFile, rc)
			// Close the file without defer to close before next iteration of loop
			outFile.Close()

			// on error, return filelist so far and the error
			if err != nil {
				return filenames, err
			}
		}
	}
	// the cycle is over, return list and no error
	return filenames, nil
}

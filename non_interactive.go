package oauth2cli

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/sync/errgroup"
	"os"
	"strings"
)

func receiveCodeViaUserInput(c *Config) (*OAuth2ConfigAndCode, error) {
	var userInput *OAuth2ConfigAndCode

	var eg errgroup.Group

	eg.Go(func() error {
		buf := bufio.NewReader(os.Stdin)
		fmt.Print(c.NonInteractivePromptText)
		input, err := buf.ReadBytes('\n')
		if err != nil {
			return err
		} else {
			cleanedInput := strings.TrimSuffix(string(input), "\n")
			decoded, err := base64.StdEncoding.DecodeString(cleanedInput)
			if err != nil {
				return err
			}

			configAndCode := OAuth2ConfigAndCode{}
			err = json.Unmarshal(decoded, &configAndCode)
			if err != nil {
				return err
			}

			userInput = &configAndCode

			return nil
		}
	})

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return userInput, nil
}

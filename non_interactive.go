package oauth2cli

import (
	"bufio"
	"fmt"
	"golang.org/x/sync/errgroup"
	"os"
)

func receiveCodeViaUserInput(c *Config) (string, error) {
	var userInput string

	var eg errgroup.Group

	eg.Go(func() error {
		buf := bufio.NewReader(os.Stdin)
		fmt.Print(c.NonInteractivePromptText)
		input, err := buf.ReadBytes('\n')
		if err != nil {
			return err
		} else {
			userInput = string(input)
			return nil
		}
	})

	if err := eg.Wait(); err != nil {
		return "", fmt.Errorf("non-interactive authorization error: %w", err)
	}

	return userInput, nil
}

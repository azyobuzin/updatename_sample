package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const (
	consumerKey      = ""
	consumerSecret   = ""
	oauthToken       = ""
	oauthTokenSecret = ""
	screenName       = ""
)

func main() {
	re := regexp.MustCompile(`^(.+)\(@` + screenName + `\)$`)

	connectUserStream(func(b []byte) {
		s := new(status)
		e := json.Unmarshal(b, s)
		if e != nil {
			return
		}

		match := re.FindStringSubmatch(s.Text)
		if len(match) != 2 {
			return
		}

		newName := strings.TrimSpace(match[1])
		e = updateName(newName)

		if e != nil {
			fmt.Print("Updating name failed: ")
			fmt.Println(e)
			return
		}

		fmt.Println(newName)
		e = updateStatus(fmt.Sprintf("@%v 「%v」とかないわ…", s.User.ScreenName, newName), s.Id)

		if e != nil {
			fmt.Print("Tweeting failed: ")
			fmt.Println(e)
		}
	})
}

var client = NewOAuthClientWithToken(consumerKey, consumerSecret, oauthToken, oauthTokenSecret)

func connectUserStream(procLine func(b []byte)) {
	req, err := client.MakeGetRequest("https://userstream.twitter.com/1.1/user.json", map[string][]string{})
	if err != nil {
		fmt.Println(err)
		return
	}

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		fmt.Println(err)
		return
	}

	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		go procLine([]byte(scanner.Text()))
	}

	if err = scanner.Err(); err != nil {
		fmt.Println(err)
	}
}

type status struct {
	Id   uint64 `json:"id"`
	Text string `json:"text"`
	User user   `json:"user"`
}

type user struct {
	ScreenName string `json:"screen_name"`
	Name       string `json:"name"`
}

func requestRestApi(req *http.Request, v interface{}) error {
	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	decoder := json.NewDecoder(res.Body)
	return decoder.Decode(v)
}

func updateName(name string) error {
	req, err := client.MakePostRequest("https://api.twitter.com/1.1/account/update_profile.json",
		map[string][]string{"name": []string{name}})

	if err != nil {
		return err
	}

	u := new(user)
	err = requestRestApi(req, u)

	if err != nil {
		return err
	}
	if u.Name != name {
		return errors.New("Failed?")
	}

	return nil
}

func updateStatus(text string, inReplyToStatusId uint64) error {
	req, err := client.MakePostRequest("https://api.twitter.com/1.1/statuses/update.json",
		map[string][]string{"status": []string{text}, "in_reply_to_status_id": []string{fmt.Sprint(inReplyToStatusId)}})

	if err != nil {
		return err
	}

	s := new(status)
	err = requestRestApi(req, s)

	if err != nil {
		return err
	}
	if s.Id == 0 {
		return errors.New("Failed?")
	}

	return nil
}

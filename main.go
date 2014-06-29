package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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
	req, e := client.MakeGetRequest("https://userstream.twitter.com/1.1/user.json", map[string][]string{})
	if e != nil {
		fmt.Println(e)
		return
	}

	res, e := http.DefaultClient.Do(req)

	if e != nil {
		fmt.Println(e)
		return
	}

	buf := new(bytes.Buffer)
	b := make([]byte, 1)
	body := res.Body
	defer body.Close()
	for {
		n, e := body.Read(b)
		if e != nil {
			fmt.Println(e)
			break
		}

		if b[0] == '\n' {
			if buf.Len() > 0 {
				procLine(buf.Bytes())
				buf.Reset()
			}
		} else {
			buf.Write(b[:n])
		}
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

func updateName(name string) error {
	req, e := client.MakePostRequest("https://api.twitter.com/1.1/account/update_profile.json",
		map[string][]string{"name": []string{name}})

	if e != nil {
		return e
	}

	res, e := http.DefaultClient.Do(req)

	if e != nil {
		return e
	}

	defer res.Body.Close()
	b, e := ioutil.ReadAll(res.Body)

	if e != nil {
		return e
	}

	u := new(user)
	e = json.Unmarshal(b, u)

	if e != nil {
		return e
	}
	if u.Name != name {
		return errors.New("Failed?")
	}

	return nil
}

func updateStatus(text string, inReplyToStatusId uint64) error {
	req, e := client.MakePostRequest("https://api.twitter.com/1.1/statuses/update.json",
		map[string][]string{"status": []string{text}, "in_reply_to_status_id": []string{fmt.Sprint(inReplyToStatusId)}})

	if e != nil {
		return e
	}

	res, e := http.DefaultClient.Do(req)

	if e != nil {
		return e
	}

	defer res.Body.Close()
	b, e := ioutil.ReadAll(res.Body)

	if e != nil {
		return e
	}

	s := new(status)
	e = json.Unmarshal(b, s)

	if e != nil {
		return e
	}
	if s.Id == 0 {
		return errors.New("Failed?")
	}

	return nil
}

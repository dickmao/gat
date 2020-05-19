package commands

import (
	"bytes"
	"text/template"

	"github.com/urfave/cli/v2"
)

func PubSubGoMod(c *cli.Context) []byte {
	return []byte(`module github.com/dickmao/helloworld

go 1.11

require (
        github.com/sendgrid/rest v2.4.1+incompatible // indirect
        github.com/sendgrid/sendgrid-go v3.5.0+incompatible
)
`)
}

func PubSubSource(c *cli.Context, apikey string) []byte {
	const templ string = `package helloworld

import (
        "context"
        "log"
        "fmt"

        "github.com/sendgrid/sendgrid-go"
        "github.com/sendgrid/sendgrid-go/helpers/mail"
)

// PubSubMessage is the payload of a Pub/Sub event.
type PubSubMessage struct {
` + "Data []byte `json:\"data\"`" + `
}

// HelloPubSub consumes a Pub/Sub message.
func HelloPubSub(ctx context.Context, m PubSubMessage) error {
        name := string(m.Data)
        if name == "" {
                name = "World"
        }
        apikey := "{{ .Apikey }}"
	from := mail.NewEmail("dickmao", "dick.r.chiang@gmail.com")
	to := mail.NewEmail("dickmao", "dick.r.chiang@gmail.com")
	message := mail.NewSingleEmail(from, "Sending with SendGrid is Fun", to, string(m.Data), fmt.Sprintf("<p>%s", string(m.Data)))
	client := sendgrid.NewSendClient(apikey)
	response, err := client.Send(message)
	if err != nil {
		log.Println(err)
	} else {
		fmt.Println(response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
	}
        return nil
}
`

	t := template.Must(template.New("PubSubSource").Parse(templ))
	var buf bytes.Buffer
	if err := t.Execute(&buf, struct {
		Apikey string
	}{
		apikey,
	}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

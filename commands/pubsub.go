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
        cloud.google.com/go v0.56.0
        github.com/sendgrid/rest v2.4.1+incompatible // indirect
        github.com/sendgrid/sendgrid-go v3.5.0+incompatible
)
`)
}

func PubSubSource(c *cli.Context, name string, address string, apikey string, timezone string) []byte {
	// the caveat that publishTime and messageId are not available
	// in the PubsubMessage. Instead, event ID and timestamp properties
	// of the metadata in the context object.
	const templ string = `package helloworld

import (
        "context"
        "log"
        "fmt"
	"path/filepath"
        "time"
        "encoding/json"

        "cloud.google.com/go/functions/metadata"
        "github.com/sendgrid/sendgrid-go"
        "github.com/sendgrid/sendgrid-go/helpers/mail"
)

// PubSubMessage is the payload of a Pub/Sub event.
type PubSubMessage struct {
` + "Data []byte `json:\"data\"`\nAttr map[string]string `json:\"attributes\"`" + `
}

// HelloPubSub consumes a Pub/Sub message.
func HelloPubSub(ctx context.Context, m PubSubMessage) error {
        from := mail.NewEmail("{{ .SendgridName }}", "{{ .SendgridAddress }}")
        to := from
        apikey := "{{ .SendgridApiKey }}"
        data := struct {
        ` + "Json map[string]interface{} `json:\"jsonPayload\"`" + `
        }{}
        json.Unmarshal(m.Data, &data)
        if data.Json["event_type"].(string) == "GCE_OPERATION_DONE" {
                meta, _ := metadata.FromContext(ctx)
                loc, _ := time.LoadLocation("{{ .Timezone }}")
                body := fmt.Sprintf("%s at %s: event %s %s%s\n", filepath.Base(meta.EventType), meta.Timestamp.In(loc).Format("2006-01-02 15:04:05"), data.Json["event_type"].(string), data.Json["event_subtype"].(string), m.Attr["branch"])
                message := mail.NewSingleEmail(from, fmt.Sprintf("[%s] %s", filepath.Base(meta.Resource.Name), data.Json["event_subtype"].(string)), to, body, fmt.Sprintf("<p>%s", body))
                client := sendgrid.NewSendClient(apikey)
                response, err := client.Send(message)
                if err != nil {
                        log.Println(err)
                } else {
                        fmt.Println(response.StatusCode)
                        fmt.Println(response.Body)
                        fmt.Println(response.Headers)
                }
        }
        return nil
}
`

	t := template.Must(template.New("PubSubSource").Parse(templ))
	var buf bytes.Buffer
	if err := t.Execute(&buf, struct {
		SendgridName    string
		SendgridAddress string
		SendgridApiKey  string
		Timezone        string
	}{
		name,
		address,
		apikey,
		timezone,
	}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

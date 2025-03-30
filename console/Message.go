package console

import "runtime"

type Message struct {
	Method string `json:"type"`
	Value  string `json:"value"`
	Caller struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"caller"`
}

func NewMessage(method string, value string) Message {

	var message Message

	message.Method = method
	message.Value = value

	// skip NewMessage()
	// skip console.<Method>()
	_, file, line, ok := runtime.Caller(2)

	if ok == true {

		message.Caller.File = file
		message.Caller.Line = line

	} else {

		message.Caller.File = "???"
		message.Caller.Line = 0

	}

	return message

}

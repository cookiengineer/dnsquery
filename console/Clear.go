package console

import "os"

func Clear() {

	// clear screen and reset cursor
	os.Stdout.WriteString("\u001b[2J\u001b[0f")

	// clear scroll buffer
	os.Stdout.WriteString("\u001b[3J")

}

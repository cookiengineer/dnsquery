package console

import "os"

func Group(message string) {

	offset := toOffset()
	message = sanitize(message)
	OFFSET++

	if COLORS == true {
		os.Stdout.WriteString("\u001b[40m" + offset + "/-" + toSeparator(message) + message + "\u001b[K\u001b[0m\n")
	} else {
		os.Stdout.WriteString(offset + "/-" + toSeparator(message) + message + "\n")
	}

}

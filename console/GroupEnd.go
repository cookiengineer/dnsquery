package console

import "os"

func GroupEnd() {

	if OFFSET > 0 {
		OFFSET--
	}

	offset := toOffset()

	if COLORS == true {
		os.Stdout.WriteString("\u001b[40m" + offset + "\\-\u001b[K\u001b[0m\n")
	} else {
		os.Stdout.WriteString(offset + "\\---\n")
	}

}

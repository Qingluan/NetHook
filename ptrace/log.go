package ptrace

import (
	"fmt"
	"log"
	"runtime"

	"github.com/fatih/color"
	"github.com/gen2brain/dlgs"
)

var (
	L = llog{
		sep:    " ",
		uselog: true,
		end:    "\n",
	}
)

type llog struct {
	sep    string
	uselog bool
	end    string
}

func (ll llog) GI(args ...interface{}) {
	greenI := color.New(color.FgGreen, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	msg := ""
	for _, a := range args {
		msg += ll.sep + green(a)
	}
	if ll.uselog {
		log.Print(greenI("[+]"), msg, ll.end)
	} else {
		fmt.Print(greenI("[+]"), msg, ll.end)
	}

}

func (ll llog) YI(args ...interface{}) {
	greenI := color.New(color.FgYellow, color.Bold).SprintFunc()
	green := color.New(color.Bold).SprintFunc()
	msg := ""
	for _, a := range args {
		msg += ll.sep + green(a)
	}
	if ll.uselog {
		log.Print(greenI("[?]"), msg, ll.end)
	} else {
		fmt.Print(greenI("[?]"), msg, ll.end)
	}

}

func (ll llog) RI(args ...interface{}) {
	greenI := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.Bold).SprintFunc()
	msg := ""
	for _, a := range args {
		msg += ll.sep + green(a)
	}
	if ll.uselog {
		log.Print(greenI("[x]"), msg, ll.end)
	} else {
		fmt.Print(greenI("[x]"), msg, ll.end)
	}

}

func (ll llog) Fatal(err error, args ...interface{}) {
	greenI := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.BgGreen, color.FgHiWhite).SprintFunc()
	mg := color.New(color.FgBlue).SprintFunc()

	_, fn, line, _ := runtime.Caller(1)
	msg := ""
	for _, a := range args {
		msg += ll.sep + mg(a)
	}
	if ll.uselog {
		log.Fatal(greenI("[", fn, " | ", line, "]"), "\nErr: ", green(err.Error()), "\nMsg:", msg, ll.end)
	} else {
		fmt.Print(greenI("[", fn, " | ", line, "]"), "\nErr: ", green(err.Error()), "\nMsg:", msg, ll.end)
	}
}

func E(err error) {
	_, fn, line, _ := runtime.Caller(1)
	dlgs.Error("Msg ::", fmt.Sprintf("%s : %d : \n%s", fn, line, err.Error()))
}

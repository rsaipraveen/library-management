package logger

import "github.com/sirupsen/logrus"

var Logger *logrus.Logger
var logLevel logrus.Level = logrus.DebugLevel

func Init() {
	Logger = logrus.New() // initializing logger
	Logger.SetLevel(logLevel)
}

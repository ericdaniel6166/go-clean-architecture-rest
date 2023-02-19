package main

import (
	"github.com/labstack/gommon/log"
	"go-clean-architecture-rest/config"
	"go-clean-architecture-rest/internal/server"
	"go-clean-architecture-rest/pkg/postgres"
	"go-clean-architecture-rest/pkg/utils"
	"os"
)

func main() {
	log.Info("Starting api server")

	configPath := utils.GetConfigPath(os.Getenv("config"))

	cfgFile, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("LoadConfig: %v", err)
	}
	cfg, err := config.ParseConfig(cfgFile)
	if err != nil {
		log.Fatalf("ParseConfig: %v", err)
	}

	//appLogger := logger.NewApiLogger(cfg)
	//
	//appLogger.InitLogger()
	//appLogger.Infof("AppVersion: %s, LogLevel: %s, Mode: %s, SSL: %v", cfg.Server.AppVersion, cfg.Logger.Level, cfg.Server.Mode, cfg.Server.SSL)

	psqlDB, err := postgres.NewPsqlDB(cfg)
	if err != nil {
		//appLogger.Fatalf("Postgresql init: %s", err)
		log.Fatalf("Postgresql init: %s", err)
	} else {
		//appLogger.Infof("Postgres connected, Status: %#v", psqlDB.Stats())
		log.Infof("Postgres connected, Status: %#v", psqlDB.Stats())
	}
	defer psqlDB.Close()

	//s := server.NewServer(cfg, psqlDB, redisClient, awsClient, appLogger)
	s := server.NewServer(cfg, psqlDB, nil, nil, nil)
	if err = s.Run(); err != nil {
		log.Fatalf("error running server: %s", err)
	}

}

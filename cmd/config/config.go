package config

import (
	"log"
	"os"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
)

var DB *gorm.DB

type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func ConnectDB() error {
	LoadEnv()

	config := DBConfig{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		Name:     os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	}

	db, err := gorm.Open("postgres", config.getConnectionString())
	if err != nil {
		return err
	}

	// Test the database connection
	if err := db.DB().Ping(); err != nil {
		return err
	}

	DB = db
	log.Println("Database connection established successfully")
	return nil
}

func (config *DBConfig) getConnectionString() string {
	return "host=" + config.Host + " port=" + config.Port +
		" user=" + config.User + " dbname=" + config.Name +
		" password=" + config.Password + " sslmode=" + config.SSLMode
}

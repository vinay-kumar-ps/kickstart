package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Define models
type User struct {
	gorm.Model
	Name            string  `json:"name"`
	Email           string  `json:"email"`
	Address         string  `json:"address"`
	UserType        string  `json:"user_type"`
	PasswordHash    string  `json:"-"`
	ProfileHeadline string  `json:"profile_headline"`
	Profile         Profile `json:"profile"`
}

type Profile struct {
	gorm.Model
	UserID            uint   `json:"-"`
	ResumeFileAddress string `json:"resume_file_address"`
	Skills            string `json:"skills"`
	Education         string `json:"education"`
	Experience        string `json:"experience"`
	Phone             string `json:"phone"`
	Extracted         bool   `json:"extracted"` 

}

type Job struct {
	gorm.Model
	Title             string    `json:"title"`
	Description       string    `json:"description"`
	PostedOn          time.Time `json:"posted_on"`
	TotalApplications int       `json:"total_applications"`
	CompanyName       string    `json:"company_name"`
	PostedBy          User      `json:"posted_by" gorm:"foreignkey:PostedByID"`
	PostedByID        uint      `json:"-"`
}

type Application struct {
	gorm.Model
	JobID       uint `json:"-"`
	Job         Job  `json:"job" gorm:"foreignkey:JobID"`
	Applicant   User `json:"applicant" gorm:"foreignkey:ApplicantID"`
	ApplicantID uint `json:"-"`
}

var (
	db            *gorm.DB
	secretKey     = []byte("secret_key")
	tokenDuration = time.Hour * 24
)

// Middleware to authenticate and set user context
func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := getCurrentUser(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Set user context for request handling
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper functions
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func generateToken(user User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":        user.ID,
		"user_type": user.UserType,
		"exp":       time.Now().Add(tokenDuration).Unix(),
	})
	return token.SignedString(secretKey)
}

func getCurrentUser(r *http.Request) (*User, error) {
	userToken := r.Header.Get("Authorization")
	if userToken == "" {
		return nil, fmt.Errorf("authorization token not provided")
	}

	tokenStr := strings.Replace(userToken, "Bearer ", "", 1)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	userID, ok := claims["id"].(float64)
	if !ok {
		return nil, fmt.Errorf("user ID not found in token claims")
	}

	var user User
	result := db.First(&user, uint(userID))
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

func saveUserToDB(user User) error {
	hashedPassword, err := hashPassword(user.PasswordHash)
	if err != nil {
		return err
	}
	user.PasswordHash = hashedPassword

	result := db.Create(&user)
	return result.Error
}

func saveAdminToDB(admin User) error {
	admin.UserType = "Admin"
	return saveUserToDB(admin)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := saveUserToDB(user); err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User signed up successfully. UserID: %d", user.ID)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var user User
	result := db.Where("email = ?", loginData.Email).First(&user)
	if result.Error != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginData.Password)) == nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := generateToken(user)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func createAdminHandler(w http.ResponseWriter, r *http.Request) {
	var admin User
	if err := json.NewDecoder(r.Body).Decode(&admin); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := saveAdminToDB(admin); err != nil {
		http.Error(w, "Error creating admin user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Admin user created successfully. UserID: %d", admin.ID)
}

func createJobHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	if user.UserType != "Admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var job Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	job.PostedOn = time.Now()
	job.PostedBy = *user

	if err := db.Create(&job).Error; err != nil {
		http.Error(w, "Error creating job", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Job created successfully. JobID: %d", job.ID)
}

func getJobsHandler(w http.ResponseWriter, r *http.Request) {
	var jobs []Job
	if err := db.Find(&jobs).Error; err != nil {
		http.Error(w, "Error fetching jobs", http.StatusInternalServerError)
		return
	}

	jobsJSON, _ := json.Marshal(jobs)
	w.WriteHeader(http.StatusOK)
	w.Write(jobsJSON)
}
func extractSkills(resumeData map[string]interface{}) string {
	if skillsData, ok := resumeData["skills"]; ok {
		switch skills := skillsData.(type) {
		case string:
			return skills
		case []interface{}:
			var skillsString string
			for _, skill := range skills {
				if s, ok := skill.(string); ok {
					skillsString += s + ", "
				}
			}
			if len(skillsString) > 2 {
				skillsString = skillsString[:len(skillsString)-2]
			}
			return skillsString
		default:
			return ""
		}
	}
	return ""
}

func extractEducation(resumeData map[string]interface{}) string {
	if educationData, ok := resumeData["education"]; ok {
		switch educations := educationData.(type) {
		case []interface{}:
			var educationString string
			for _, edu := range educations {
				if eduMap, ok := edu.(map[string]interface{}); ok {
					if institution, instOk := eduMap["name"].(string); instOk {
						educationString += institution + ", "
					}
				}
			}
			if len(educationString) > 2 {
				educationString = educationString[:len(educationString)-2]
			}
			return educationString
		default:
			return ""
		}
	}
	return ""
}

func extractExperience(resumeData map[string]interface{}) string {
	if experienceData, ok := resumeData["experience"]; ok {
		switch experiences := experienceData.(type) {
		case []interface{}:
			var experienceString string
			for _, exp := range experiences {
				if expMap, ok := exp.(map[string]interface{}); ok {
					if companyName, compOk := expMap["name"].(string); compOk {
						experienceString += companyName + ", "
					}
				}
			}
			if len(experienceString) > 2 {
				experienceString = experienceString[:len(experienceString)-2]
			}
			return experienceString
		default:
			return ""
		}
	}
	return ""
}

func extractPhone(resumeData map[string]interface{}) string {
	if phone, ok := resumeData["phone"].(string); ok {
		return phone
	}
	return ""
}

func applyJobHandler(w http.ResponseWriter, r *http.Request) {
	var application Application
	if err := json.NewDecoder(r.Body).Decode(&application); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := r.Context().Value("user").(*User)
	application.ApplicantID = user.ID

	if err := db.Create(&application).Error; err != nil {
		http.Error(w, "Error applying for the job", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Applied for the job successfully")

}

// Third-party API details
const (
	apiEndpoint = "https://api.apilayer.com/resume_parser/upload"
	apiKey      = "0bWeisRWoLj3UdXt3MXMSMWptYFIpQfS"
)

// Helper function to extract resume details using third-party API
func extractResumeDetails(fileURL string, resumeData map[string]interface{}) (Profile, error) {
	// Existing code to fetch resume details from API

	// Process the resumeData and create a Profile struct
	profile := Profile{
		ResumeFileAddress: fileURL,
		Skills:            extractSkills(resumeData),
		Education:         extractEducation(resumeData),
		Experience:        extractExperience(resumeData),
		Phone:             extractPhone(resumeData),
		Extracted:         true, // Set the extracted flag
	}

	// Save the profile to the database
	result := db.Create(&profile)
	if result.Error != nil {
		return Profile{}, result.Error
	}

	return profile, nil
}

func getExtractedResumeDetailsHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is an admin
	user := r.Context().Value("user").(*User)
	if user.UserType != "Admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Fetch all profiles with extracted resume details
	var profiles []Profile
	result := db.Where("extracted = ?", true).Find(&profiles)
	if result.Error != nil {
		http.Error(w, "Error fetching extracted resume details", http.StatusInternalServerError)
		return
	}

	// Send the extracted resume details as JSON response
	profilesJSON, _ := json.Marshal(profiles)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(profilesJSON)
}


func main() {
	dbInit()

	r := mux.NewRouter()

	r.HandleFunc("/signup", signupHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/admin/create", createAdminHandler).Methods("POST")
	r.HandleFunc("/jobs/create", createJobHandler).Methods("POST")
	r.HandleFunc("/jobs", getJobsHandler).Methods("GET")
	r.HandleFunc("/jobs/apply", applyJobHandler).Methods("POST")
	r.HandleFunc("/admin/resume/details", getExtractedResumeDetailsHandler).Methods("GET")

	fmt.Println("Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func dbInit() {
	var err error
	db, err = gorm.Open(sqlite.Open("jobs.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}
	db.AutoMigrate(&User{}, &Profile{}, &Job{}, &Application{})
}

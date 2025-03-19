package main

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/mailgun/mailgun-go/v4"
	"github.com/sirupsen/logrus"
)

type NotificationEvent string

const (
	NotificationEventCheckoutCreated   NotificationEvent = "checkout.created"
	NotificationEventCheckoutPaid      NotificationEvent = "checkout.paid"
	NotificationEventCheckoutUnderpaid NotificationEvent = "checkout.underpaid"
	NotificationEventCheckoutOverpaid  NotificationEvent = "checkout.overpaid"
	NotificationEventCheckoutExpired   NotificationEvent = "checkout.expired"
)

var AllNotificationEvents = []NotificationEvent{
	NotificationEventCheckoutCreated,
	NotificationEventCheckoutPaid,
	NotificationEventCheckoutUnderpaid,
	NotificationEventCheckoutOverpaid,
	NotificationEventCheckoutExpired,
}

type NotificationChannelType string

const (
	NotificationChannelEmail NotificationChannelType = "email"
	NotificationChannelSlack NotificationChannelType = "slack"
	NotificationChannelNostr NotificationChannelType = "nostr"
)

type NotificationEventList []NotificationEvent

func (ne NotificationEventList) Value() (driver.Value, error) {
	return json.Marshal(ne)
}

func (ne *NotificationEventList) Scan(value interface{}) error {
	if value == nil {
		*ne = []NotificationEvent{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan NotificationEventList: %v", value)
	}

	return json.Unmarshal(bytes, ne)
}

type NotificationSettings struct {
	ID          uuid.UUID               `db:"id" json:"id"`
	UserID      uuid.UUID               `db:"user_id" json:"user_id"`
	AccountID   uuid.UUID               `db:"account_id" json:"account_id"`
	ChannelType NotificationChannelType `db:"channel_type" json:"channel_type"`
	Enabled     bool                    `db:"enabled" json:"enabled"`
	Events      NotificationEventList   `db:"events" json:"events"`
	Email       string                  `db:"email" json:"email,omitempty"`
	CreatedAt   time.Time               `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time               `db:"updated_at" json:"updated_at"`
	DeletedAt   *time.Time              `db:"deleted_at" json:"deleted_at,omitempty"`
}

type NotificationCache struct {
	cache sync.Map
}

func (c *NotificationCache) GetByAccount(accountID uuid.UUID) (map[NotificationChannelType]*NotificationSettings, bool) {
	value, ok := c.cache.Load(accountID)
	if !ok {
		return nil, false
	}
	settings, ok := value.(map[NotificationChannelType]*NotificationSettings)
	return settings, ok
}

func (c *NotificationCache) SetForAccount(accountID uuid.UUID, settings map[NotificationChannelType]*NotificationSettings) {
	c.cache.Store(accountID, settings)
}

func (c *NotificationCache) InvalidateForAccount(accountID uuid.UUID) {
	c.cache.Delete(accountID)
}

type NotificationRepository struct{}

func (r *NotificationRepository) Create(settings *NotificationSettings) (*NotificationSettings, error) {
	settings.ID = uuid.New()
	eventsJSON, err := json.Marshal(settings.Events)
	if err != nil {
		return nil, err
	}

	err = db.QueryRowx(`
		INSERT INTO notification_settings (
			id, user_id, account_id, channel_type, enabled, 
			events, email, created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		) RETURNING id`,
		settings.ID, settings.UserID, settings.AccountID, settings.ChannelType, settings.Enabled,
		eventsJSON, settings.Email, settings.CreatedAt, settings.UpdatedAt, settings.DeletedAt,
	).Scan(&settings.ID)

	return settings, err
}

func (r *NotificationRepository) Get(id uuid.UUID) (*NotificationSettings, error) {
	settings := &NotificationSettings{}
	err := db.Get(settings, `
		SELECT id, user_id, account_id, channel_type, enabled, 
			events, email, created_at, updated_at, deleted_at
		FROM notification_settings
		WHERE id = $1 AND deleted_at IS NULL`,
		id,
	)
	return settings, err
}

func (r *NotificationRepository) GetByAccountAndChannel(accountID uuid.UUID, channelType NotificationChannelType) (*NotificationSettings, error) {
	settings := &NotificationSettings{}
	err := db.Get(settings, `
		SELECT id, user_id, account_id, channel_type, enabled, 
			events, email, created_at, updated_at, deleted_at
		FROM notification_settings
		WHERE account_id = $1 AND channel_type = $2 AND deleted_at IS NULL`,
		accountID, channelType,
	)
	return settings, err
}

func (r *NotificationRepository) GetByAccount(accountID uuid.UUID) ([]*NotificationSettings, error) {
	settings := []*NotificationSettings{}
	err := db.Select(&settings, `
		SELECT id, user_id, account_id, channel_type, enabled, 
			events, email, created_at, updated_at, deleted_at
		FROM notification_settings
		WHERE account_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`,
		accountID,
	)
	return settings, err
}

func (r *NotificationRepository) GetByAccountAndEvent(accountID uuid.UUID, event NotificationEvent) ([]*NotificationSettings, error) {
	settings := []*NotificationSettings{}
	err := db.Select(&settings, `
		SELECT id, user_id, account_id, channel_type, enabled, 
			events, email, created_at, updated_at, deleted_at
		FROM notification_settings
		WHERE account_id = $1 AND deleted_at IS NULL AND enabled = true
			AND events::jsonb ? $2
		ORDER BY created_at DESC`,
		accountID, event,
	)
	return settings, err
}

func (r *NotificationRepository) Update(settings *NotificationSettings) error {
	eventsJSON, err := json.Marshal(settings.Events)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		UPDATE notification_settings SET 
			enabled = $1,
			events = $2,
			email = $3,
			updated_at = $4,
			deleted_at = $5
		WHERE id = $6`,
		settings.Enabled, eventsJSON, settings.Email,
		settings.UpdatedAt, settings.DeletedAt, settings.ID,
	)
	return err
}

func (r *NotificationRepository) Delete(id uuid.UUID) error {
	now := time.Now()
	_, err := db.Exec(`
		UPDATE notification_settings SET 
			deleted_at = $1
		WHERE id = $2`,
		now, id,
	)
	return err
}

type NotificationAdapter interface {
	Send(recipient string, subject string, htmlBody string, textBody string) error
	Initialize(config map[string]string) error
}

type MailgunAdapter struct {
	client      *mailgun.MailgunImpl
	domain      string
	senderEmail string
	senderName  string
	initialized bool
}

func (a *MailgunAdapter) Initialize(config map[string]string) error {
	domain, ok := config["domain"]
	if !ok {
		return fmt.Errorf("mailgun domain is required")
	}

	apiKey, ok := config["api_key"]
	if !ok {
		return fmt.Errorf("mailgun api_key is required")
	}

	senderEmail, ok := config["sender_email"]
	if !ok {
		return fmt.Errorf("sender_email is required")
	}

	senderName := config["sender_name"]
	if senderName == "" {
		senderName = "Bitcoin Payment Processor"
	}

	a.domain = domain
	a.client = mailgun.NewMailgun(domain, apiKey)
	a.senderEmail = senderEmail
	a.senderName = senderName
	a.initialized = true

	return nil
}

func (a *MailgunAdapter) Send(recipient string, subject string, htmlBody string, textBody string) error {
	if !a.initialized {
		return fmt.Errorf("mailgun adapter not initialized")
	}

	sender := fmt.Sprintf("%s <%s>", a.senderName, a.senderEmail)
	message := a.client.NewMessage(sender, subject, textBody, recipient)
	message.SetHtml(htmlBody)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, _, err := a.client.Send(ctx, message)
	return err
}

type NotificationService struct {
	adapters       map[NotificationChannelType]NotificationAdapter
	emailTemplates map[NotificationEvent]*template.Template
	templateDir    string
}

var notificationRepository = &NotificationRepository{}
var notificationCache = &NotificationCache{}
var notificationService *NotificationService

func NewNotificationService() *NotificationService {
	service := &NotificationService{
		adapters:       make(map[NotificationChannelType]NotificationAdapter),
		emailTemplates: make(map[NotificationEvent]*template.Template),
		templateDir:    "templates/notification",
	}

	// Read MAIL_DRIVER from environment variables
	mailDriver := os.Getenv("MAIL_DRIVER")
	if mailDriver == "mailgun" {
		mailgunAdapter := &MailgunAdapter{}
		// Initialize Mailgun with credentials from environment variables
		config := map[string]string{
			"domain":       os.Getenv("MAILGUN_DOMAIN"),
			"api_key":      os.Getenv("MAILGUN_API_KEY"),
			"sender_email": os.Getenv("MAILGUN_SENDER_EMAIL"),
			"sender_name":  os.Getenv("MAILGUN_SENDER_NAME"),
		}
		if err := mailgunAdapter.Initialize(config); err != nil {
			fmt.Printf("Error initializing Mailgun adapter: %v\n", err)
			return nil
		}
		service.RegisterAdapter(NotificationChannelEmail, mailgunAdapter)
		fmt.Println("Mailgun adapter initialized")
	} else {
		// Handle other mail drivers or set a default
		fmt.Printf("Unsupported mail driver: %s\n", mailDriver)
	}

	service.loadTemplates()

	return service
}

func (s *NotificationService) RegisterAdapter(channelType NotificationChannelType, adapter NotificationAdapter) {
	s.adapters[channelType] = adapter
}

func (s *NotificationService) InitializeAdapter(channelType NotificationChannelType, config map[string]string) error {
	adapter, ok := s.adapters[channelType]
	if !ok {
		return fmt.Errorf("no adapter registered for channel type: %s", channelType)
	}

	return adapter.Initialize(config)
}

func (s *NotificationService) loadTemplates() {
	baseTemplatePath := filepath.Join(s.templateDir, "base.html")

	// Load each template with the base template
	templateFiles := map[NotificationEvent]string{
		NotificationEventCheckoutCreated:   "checkout_created.html",
		NotificationEventCheckoutPaid:      "checkout_paid.html",
		NotificationEventCheckoutUnderpaid: "checkout_underpaid.html",
		NotificationEventCheckoutOverpaid:  "checkout_overpaid.html",
		NotificationEventCheckoutExpired:   "checkout_expired.html",
	}

	for event, filename := range templateFiles {
		// Parse both the base template and the specific template
		templatePath := filepath.Join(s.templateDir, filename)
		tmpl, err := template.ParseFiles(baseTemplatePath, templatePath)
		if err != nil {
			fmt.Printf("Error parsing templates for event %s: %v\n", event, err)
			continue
		}

		s.emailTemplates[event] = tmpl
	}
}

func (s *NotificationService) GetOrCreateSettings(accountID uuid.UUID, userID uuid.UUID, channelType NotificationChannelType) (*NotificationSettings, error) {
	settings, err := notificationRepository.GetByAccountAndChannel(accountID, channelType)
	if err == nil {
		return settings, nil
	}

	user, err := userRepository.Get(userID) // Assuming you have a user repository to get user details
	if err != nil {
		return nil, err
	}

	settings = &NotificationSettings{
		ID:          uuid.New(),
		UserID:      userID,
		AccountID:   accountID,
		ChannelType: channelType,
		Enabled:     true,
		Events:      NotificationEventList{},
		Email:       user.Email, // Set the email from the user
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return notificationRepository.Create(settings)
}

func (s *NotificationService) UpdateSettings(settings *NotificationSettings) error {
	settings.UpdatedAt = time.Now()

	err := notificationRepository.Update(settings)
	if err != nil {
		return err
	}

	notificationCache.InvalidateForAccount(settings.AccountID)
	return nil
}

func (s *NotificationService) GetSettingsByAccount(accountID uuid.UUID) (map[NotificationChannelType]*NotificationSettings, error) {
	if cachedSettings, found := notificationCache.GetByAccount(accountID); found {
		return cachedSettings, nil
	}

	settingsArray, err := notificationRepository.GetByAccount(accountID)
	if err != nil {
		return nil, err
	}

	settingsMap := make(map[NotificationChannelType]*NotificationSettings)
	for _, settings := range settingsArray {
		settingsMap[settings.ChannelType] = settings
	}

	notificationCache.SetForAccount(accountID, settingsMap)
	return settingsMap, nil
}

func (s *NotificationService) GetSettingsByAccountAndChannel(accountID uuid.UUID, channelType NotificationChannelType) (*NotificationSettings, error) {
	if cachedSettings, found := notificationCache.GetByAccount(accountID); found {
		if settings, ok := cachedSettings[channelType]; ok {
			return settings, nil
		}
	}

	settings, err := notificationRepository.GetByAccountAndChannel(accountID, channelType)
	if err != nil {
		return nil, err
	}

	return settings, nil
}

func (s *NotificationService) DeleteSettings(id uuid.UUID) error {
	settings, err := notificationRepository.Get(id)
	if err != nil {
		return err
	}

	err = notificationRepository.Delete(id)
	if err != nil {
		return err
	}

	notificationCache.InvalidateForAccount(settings.AccountID)
	return nil
}

func (s *NotificationService) SendNotification(event NotificationEvent, accountID uuid.UUID, data interface{}) {
	settings, err := notificationRepository.GetByAccountAndEvent(accountID, event)
	if err != nil || len(settings) == 0 {
		return
	}

	for _, setting := range settings {
		if !setting.Enabled {
			continue
		}

		switch setting.ChannelType {
		case NotificationChannelEmail:
			s.sendEmailNotification(event, setting, data)
		default:
			fmt.Printf("Unsupported notification channel type: %s\n", setting.ChannelType)
		}
	}
}

func (s *NotificationService) sendEmailNotification(event NotificationEvent, settings *NotificationSettings, data interface{}) {
	if settings.Email == "" {
		return
	}

	adapter, ok := s.adapters[NotificationChannelEmail]
	if !ok {
		logrus.Warn("No adapter registered for email notifications")
		return
	}

	template, ok := s.emailTemplates[event]
	if !ok {
		logrus.Warnf("No template found for event: %s", event)
		return
	}

	templateData, subject := s.prepareTemplateData(event, data)

	var htmlBuffer bytes.Buffer
	err := template.Execute(&htmlBuffer, templateData)
	if err != nil {
		logrus.Errorf("Error executing template: %v", err)
		return
	}

	htmlBody := htmlBuffer.String()
	textBody := s.generateTextVersion(templateData)

	logrus.Infof("Sending email to: %s with subject: %s", settings.Email, subject)
	err = adapter.Send(settings.Email, subject, htmlBody, textBody)
	if err != nil {
		logrus.Errorf("Error sending email notification: %v", err)
	} else {
		logrus.Infof("Email sent successfully to: %s", settings.Email)
	}
}

func (s *NotificationService) prepareTemplateData(event NotificationEvent, data interface{}) (map[string]interface{}, string) {
	templateData := map[string]interface{}{
		"Year": time.Now().Year(),
	}

	var subject string

	switch event {
	case NotificationEventCheckoutCreated:
		checkout, ok := data.(*Checkout)
		if ok {
			subject = "New Checkout Created"
			templateData["Title"] = "New Checkout Created"
			templateData["Subject"] = subject
			templateData["CheckoutID"] = checkout.ID.String()
			templateData["Amount"] = float64(checkout.Amount) / 100000000
			templateData["CreatedAt"] = checkout.CreatedAt.Format("January 2, 2006 at 3:04 PM")
			templateData["ExpiresAt"] = checkout.ExpiresAt.Format("January 2, 2006 at 3:04 PM")
		}

	case NotificationEventCheckoutPaid:
		checkout, ok := data.(*Checkout)
		if ok {
			subject = "Checkout Payment Received"
			templateData["Title"] = "Payment Received"
			templateData["Subject"] = subject
			templateData["CheckoutID"] = checkout.ID.String()
			templateData["Amount"] = float64(checkout.Amount) / 100000000
			templateData["ReceivedAmount"] = float64(checkout.ReceivedAmount) / 100000000
			templateData["State"] = string(checkout.State)
			templateData["UpdatedAt"] = checkout.UpdatedAt.Format("January 2, 2006 at 3:04 PM")
		}

	case NotificationEventCheckoutExpired:
		checkout, ok := data.(*Checkout)
		if ok {
			subject = "Checkout Expired"
			templateData["Title"] = "Checkout Expired"
			templateData["Subject"] = subject
			templateData["CheckoutID"] = checkout.ID.String()
			templateData["Amount"] = float64(checkout.Amount) / 100000000
			templateData["CreatedAt"] = checkout.CreatedAt.Format("January 2, 2006 at 3:04 PM")
			templateData["UpdatedAt"] = checkout.UpdatedAt.Format("January 2, 2006 at 3:04 PM")
		}

	default:
		subject = "Notification from Bitcoin Payment Processor"
		templateData["Title"] = "Notification"
		templateData["Subject"] = subject
		templateData["Message"] = "You have a new notification from your Bitcoin Payment Processor."
	}

	return templateData, subject
}

func (s *NotificationService) generateTextVersion(templateData map[string]interface{}) string {
	title, _ := templateData["Title"].(string)
	content, _ := templateData["Content"].(template.HTML)

	textContent := fmt.Sprintf("%s\n\n%s\n\nThis is an automated notification from your Bitcoin Payment Processor.\n© %d Bitcoin Payment Processor",
		title,
		content,
		templateData["Year"])

	return textContent
}

type NotificationHandler struct {
	Validator *validator.Validate
}

var notificationHandler = &NotificationHandler{
	Validator: validator.New(),
}

func (h *NotificationHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountId")
	channelType := r.URL.Query().Get("channel")

	if accountIDStr == "" {
		JsonResponse(w, http.StatusBadRequest, "Account ID is required", nil)
		return
	}

	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
		return
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to access notification settings for this account", nil)
		return
	}

	if channelType != "" {
		settings, err := notificationService.GetSettingsByAccountAndChannel(accountID, NotificationChannelType(channelType))
		if err != nil {
			JsonResponse(w, http.StatusNotFound, "Notification settings not found", err.Error())
			return
		}

		JsonResponse(w, http.StatusOK, "Notification settings retrieved successfully", settings)
		return
	}

	settings, err := notificationService.GetSettingsByAccount(accountID)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving notification settings", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Notification settings retrieved successfully", settings)
}

func (h *NotificationHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AccountID   uuid.UUID               `json:"account_id" validate:"required"`
		ChannelType NotificationChannelType `json:"channel_type" validate:"required"`
		Enabled     bool                    `json:"enabled"`
		Events      []NotificationEvent     `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request format", err.Error())
		return
	}

	if err := h.Validator.Struct(input); err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid request data", err.Error())
		return
	}

	validEvents := make(map[string]bool)
	for _, event := range AllNotificationEvents {
		validEvents[string(event)] = true
	}

	for _, event := range input.Events {
		if !validEvents[string(event)] {
			JsonResponse(w, http.StatusBadRequest, "Invalid event type", fmt.Sprintf("Event '%s' is not a valid event type", event))
			return
		}
	}

	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving user", err.Error())
		return
	}

	account, err := accountService.Get(input.AccountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	if account.UserID != user.ID {
		JsonResponse(w, http.StatusForbidden, "You are not authorized to update notification settings for this account", nil)
		return
	}

	settings, err := notificationService.GetOrCreateSettings(input.AccountID, user.ID, input.ChannelType)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving notification settings", err.Error())
		return
	}

	settings.Enabled = input.Enabled
	settings.Events = input.Events

	// Set the email from the user instead of the input
	settings.Email = user.Email // Assuming user.Email contains the user's email address

	err = notificationService.UpdateSettings(settings)
	if err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error updating notification settings", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, "Notification settings updated successfully", settings)
}

func init() {
	notificationService = NewNotificationService()
}

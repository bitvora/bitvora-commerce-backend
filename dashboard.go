package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// SalesDataPoint represents a single data point for sales analytics
type SalesDataPoint struct {
	Timestamp  time.Time `json:"timestamp"`
	Amount     int64     `json:"amount"`
	Count      int       `json:"count"`
	HourOfDay  int       `json:"hour_of_day,omitempty"`
	DayOfWeek  int       `json:"day_of_week,omitempty"`
	DayOfMonth int       `json:"day_of_month,omitempty"`
	Month      int       `json:"month,omitempty"`
	Year       int       `json:"year,omitempty"`
}

// SalesSummary represents a summary of sales for a given period
type SalesSummary struct {
	TotalAmount int64            `json:"total_amount"`
	TotalCount  int              `json:"total_count"`
	StartTime   time.Time        `json:"start_time"`
	EndTime     time.Time        `json:"end_time"`
	DataPoints  []SalesDataPoint `json:"data_points"`
}

// WeeklySalesDataPoint represents a single day's data in a weekly summary
type WeeklySalesDataPoint struct {
	Date       time.Time `json:"date"`
	Amount     int64     `json:"amount"`
	Count      int       `json:"count"`
	DayOfWeek  int       `json:"day_of_week"`
	DayOfMonth int       `json:"day_of_month"`
	Month      int       `json:"month"`
	Year       int       `json:"year"`
}

// WeeklySalesSummary represents a summary of sales for a 7-day period
type WeeklySalesSummary struct {
	TotalAmount int64                  `json:"total_amount"`
	TotalCount  int                    `json:"total_count"`
	StartDate   time.Time              `json:"start_date"`
	EndDate     time.Time              `json:"end_date"`
	DataPoints  []WeeklySalesDataPoint `json:"data_points"`
}

// MonthlySalesDataPoint represents a single month's data in a monthly summary
type MonthlySalesDataPoint struct {
	Month     time.Time `json:"month"` // First day of the month
	Amount    int64     `json:"amount"`
	Count     int       `json:"count"`
	MonthName string    `json:"month_name"` // e.g., "January"
	MonthNum  int       `json:"month_num"`  // 1-12
	Year      int       `json:"year"`
}

// MonthlySalesSummary represents a summary of sales for a multi-month period
type MonthlySalesSummary struct {
	TotalAmount int64                   `json:"total_amount"`
	TotalCount  int                     `json:"total_count"`
	StartMonth  time.Time               `json:"start_month"`
	EndMonth    time.Time               `json:"end_month"`
	DataPoints  []MonthlySalesDataPoint `json:"data_points"`
}

// DashboardRepository handles database operations for dashboard analytics
type DashboardRepository struct{}

// GetSalesForDate retrieves sales data for a specific date, grouped by hour
func (r *DashboardRepository) GetSalesForDate(accountID uuid.UUID, date time.Time) (*SalesSummary, error) {
	// Get date boundaries in UTC
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	// Create the summary result container
	summary := &SalesSummary{
		StartTime:  startOfDay,
		EndTime:    endOfDay,
		DataPoints: make([]SalesDataPoint, 24), // One data point per hour
	}

	// Initialize data points for each hour
	for i := 0; i < 24; i++ {
		hourTime := startOfDay.Add(time.Duration(i) * time.Hour)
		summary.DataPoints[i] = SalesDataPoint{
			Timestamp:  hourTime,
			Amount:     0,
			Count:      0,
			HourOfDay:  i,
			DayOfWeek:  int(hourTime.Weekday()),
			DayOfMonth: hourTime.Day(),
			Month:      int(hourTime.Month()),
			Year:       hourTime.Year(),
		}
	}

	// Query for total amount and count
	var totalAmount int64
	var totalCount int
	err := db.QueryRow(`
		SELECT COALESCE(SUM(amount), 0), COUNT(*)
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at < $5
		AND deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfDay, endOfDay).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total sales: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for hourly breakdown
	rows, err := db.Query(`
		SELECT 
			EXTRACT(HOUR FROM created_at) as hour,
			COALESCE(SUM(amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at < $5
		AND deleted_at IS NULL
		GROUP BY EXTRACT(HOUR FROM created_at)
		ORDER BY hour`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfDay, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying hourly sales: %w", err)
	}
	defer rows.Close()

	// Populate hourly data
	for rows.Next() {
		var hour int
		var amount int64
		var count int
		if err := rows.Scan(&hour, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning hourly sales row: %w", err)
		}

		if hour >= 0 && hour < 24 {
			summary.DataPoints[hour].Amount = amount
			summary.DataPoints[hour].Count = count
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through hourly sales rows: %w", err)
	}

	return summary, nil
}

// GetSalesToday retrieves sales data for today, grouped by hour
func (r *DashboardRepository) GetSalesToday(accountID uuid.UUID) (*SalesSummary, error) {
	// Reuse the GetSalesForDate method with today's date
	return r.GetSalesForDate(accountID, time.Now().UTC())
}

// GetSalesDateRange retrieves sales data for a custom date range
func (r *DashboardRepository) GetSalesDateRange(accountID uuid.UUID, startDate, endDate time.Time, groupBy string) (*SalesSummary, error) {
	// Implementation for date range queries would go here
	// This would support different grouping (hourly, daily, weekly, monthly)
	// For now we'll just return a placeholder
	return &SalesSummary{
		StartTime:   startDate,
		EndTime:     endDate,
		TotalAmount: 0,
		TotalCount:  0,
		DataPoints:  []SalesDataPoint{},
	}, nil
}

// GetLast7DaysSales retrieves sales data for the 7 days ending on the specified date
func (r *DashboardRepository) GetLast7DaysSales(accountID uuid.UUID, endDate time.Time) (*WeeklySalesSummary, error) {
	// Get date boundaries in UTC
	endOfDay := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 999999999, time.UTC)
	startDate := endOfDay.AddDate(0, 0, -6) // Go back 6 days to get 7 days total
	startOfPeriod := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)

	// Create the summary result container
	summary := &WeeklySalesSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfDay,
		DataPoints: make([]WeeklySalesDataPoint, 7), // One data point per day
	}

	// Initialize data points for each day
	for i := 0; i < 7; i++ {
		dayDate := startOfPeriod.AddDate(0, 0, i)
		summary.DataPoints[i] = WeeklySalesDataPoint{
			Date:       dayDate,
			Amount:     0,
			Count:      0,
			DayOfWeek:  int(dayDate.Weekday()),
			DayOfMonth: dayDate.Day(),
			Month:      int(dayDate.Month()),
			Year:       dayDate.Year(),
		}
	}

	// Query for total amount and count for the 7-day period
	var totalAmount int64
	var totalCount int
	err := db.QueryRow(`
		SELECT COALESCE(SUM(amount), 0), COUNT(*)
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at <= $5
		AND deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total sales for 7 days: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for daily breakdown - use TO_CHAR to format the date properly
	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE(created_at), 'YYYY-MM-DD') as sale_date,
			COALESCE(SUM(amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at <= $5
		AND deleted_at IS NULL
		GROUP BY DATE(created_at)
		ORDER BY sale_date`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying daily sales: %w", err)
	}
	defer rows.Close()

	// Process query results directly into data points
	for rows.Next() {
		var dateStr string
		var amount int64
		var count int
		if err := rows.Scan(&dateStr, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning daily sales row: %w", err)
		}

		// Parse the date string to a time.Time
		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing date: %w", err)
		}

		// Find the corresponding data point by comparing dates
		for i := range summary.DataPoints {
			// Compare dates by formatting them to strings for equality check
			if summary.DataPoints[i].Date.Format("2006-01-02") == date.Format("2006-01-02") {
				summary.DataPoints[i].Amount = amount
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through daily sales rows: %w", err)
	}

	return summary, nil
}

// GetLast30DaysSales retrieves sales data for the 30 days ending on the specified date
func (r *DashboardRepository) GetLast30DaysSales(accountID uuid.UUID, endDate time.Time) (*WeeklySalesSummary, error) {
	// Get date boundaries in UTC
	endOfDay := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 999999999, time.UTC)
	startDate := endOfDay.AddDate(0, 0, -29) // Go back 29 days to get 30 days total
	startOfPeriod := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)

	// Create the summary result container
	summary := &WeeklySalesSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfDay,
		DataPoints: make([]WeeklySalesDataPoint, 30), // One data point per day
	}

	// Initialize data points for each day
	for i := 0; i < 30; i++ {
		dayDate := startOfPeriod.AddDate(0, 0, i)
		summary.DataPoints[i] = WeeklySalesDataPoint{
			Date:       dayDate,
			Amount:     0,
			Count:      0,
			DayOfWeek:  int(dayDate.Weekday()),
			DayOfMonth: dayDate.Day(),
			Month:      int(dayDate.Month()),
			Year:       dayDate.Year(),
		}
	}

	// Query for total amount and count for the 30-day period
	var totalAmount int64
	var totalCount int
	err := db.QueryRow(`
		SELECT COALESCE(SUM(amount), 0), COUNT(*)
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at <= $5
		AND deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total sales for 30 days: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for daily breakdown
	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE(created_at), 'YYYY-MM-DD') as sale_date,
			COALESCE(SUM(amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at <= $5
		AND deleted_at IS NULL
		GROUP BY DATE(created_at)
		ORDER BY sale_date`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying daily sales: %w", err)
	}
	defer rows.Close()

	// Process query results directly into data points
	for rows.Next() {
		var dateStr string
		var amount int64
		var count int
		if err := rows.Scan(&dateStr, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning daily sales row: %w", err)
		}

		// Parse the date string to a time.Time
		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing date: %w", err)
		}

		// Find the corresponding data point by comparing dates
		for i := range summary.DataPoints {
			// Compare dates by formatting them to strings for equality check
			if summary.DataPoints[i].Date.Format("2006-01-02") == date.Format("2006-01-02") {
				summary.DataPoints[i].Amount = amount
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through daily sales rows: %w", err)
	}

	return summary, nil
}

// GetLast6MonthsSales retrieves sales data for the 6 months ending on the specified date
func (r *DashboardRepository) GetLast6MonthsSales(accountID uuid.UUID, endDate time.Time) (*MonthlySalesSummary, error) {
	// Get month boundaries
	endOfMonth := time.Date(endDate.Year(), endDate.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0).Add(-time.Nanosecond)
	startMonth := endOfMonth.AddDate(0, -5, 0) // Go back 5 months to get 6 months total
	startOfPeriod := time.Date(startMonth.Year(), startMonth.Month(), 1, 0, 0, 0, 0, time.UTC)

	// Create the summary result container
	summary := &MonthlySalesSummary{
		StartMonth: startOfPeriod,
		EndMonth:   endOfMonth,
		DataPoints: make([]MonthlySalesDataPoint, 6), // One data point per month
	}

	// Month names
	monthNames := []string{
		"January", "February", "March", "April", "May", "June",
		"July", "August", "September", "October", "November", "December",
	}

	// Initialize data points for each month
	for i := 0; i < 6; i++ {
		monthDate := startOfPeriod.AddDate(0, i, 0)
		monthIndex := int(monthDate.Month()) - 1 // 0-based index for monthNames

		summary.DataPoints[i] = MonthlySalesDataPoint{
			Month:     monthDate,
			Amount:    0,
			Count:     0,
			MonthName: monthNames[monthIndex],
			MonthNum:  int(monthDate.Month()),
			Year:      monthDate.Year(),
		}
	}

	// Query for total amount and count for the 6-month period
	var totalAmount int64
	var totalCount int
	err := db.QueryRow(`
		SELECT COALESCE(SUM(amount), 0), COUNT(*)
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at <= $5
		AND deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total sales for 6 months: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for monthly breakdown
	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE_TRUNC('month', created_at), 'YYYY-MM-DD') as month_start,
			COALESCE(SUM(amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at <= $5
		AND deleted_at IS NULL
		GROUP BY DATE_TRUNC('month', created_at)
		ORDER BY month_start`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth)

	if err != nil {
		return nil, fmt.Errorf("error querying monthly sales: %w", err)
	}
	defer rows.Close()

	// Process query results directly into data points
	for rows.Next() {
		var monthStr string
		var amount int64
		var count int
		if err := rows.Scan(&monthStr, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning monthly sales row: %w", err)
		}

		// Parse the month string to a time.Time
		monthDate, err := time.Parse("2006-01-02", monthStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing month date: %w", err)
		}

		// Find the corresponding data point by comparing month and year
		for i := range summary.DataPoints {
			// Compare month and year for equality
			if summary.DataPoints[i].Month.Month() == monthDate.Month() &&
				summary.DataPoints[i].Month.Year() == monthDate.Year() {
				summary.DataPoints[i].Amount = amount
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through monthly sales rows: %w", err)
	}

	return summary, nil
}

// GetLast12MonthsSales retrieves sales data for the 12 months ending on the specified date
func (r *DashboardRepository) GetLast12MonthsSales(accountID uuid.UUID, endDate time.Time) (*MonthlySalesSummary, error) {
	// Get month boundaries
	endOfMonth := time.Date(endDate.Year(), endDate.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0).Add(-time.Nanosecond)
	startMonth := endOfMonth.AddDate(0, -11, 0) // Go back 11 months to get 12 months total
	startOfPeriod := time.Date(startMonth.Year(), startMonth.Month(), 1, 0, 0, 0, 0, time.UTC)

	// Create the summary result container
	summary := &MonthlySalesSummary{
		StartMonth: startOfPeriod,
		EndMonth:   endOfMonth,
		DataPoints: make([]MonthlySalesDataPoint, 12), // One data point per month
	}

	// Month names
	monthNames := []string{
		"January", "February", "March", "April", "May", "June",
		"July", "August", "September", "October", "November", "December",
	}

	// Initialize data points for each month
	for i := 0; i < 12; i++ {
		monthDate := startOfPeriod.AddDate(0, i, 0)
		monthIndex := int(monthDate.Month()) - 1 // 0-based index for monthNames

		summary.DataPoints[i] = MonthlySalesDataPoint{
			Month:     monthDate,
			Amount:    0,
			Count:     0,
			MonthName: monthNames[monthIndex],
			MonthNum:  int(monthDate.Month()),
			Year:      monthDate.Year(),
		}
	}

	// Query for total amount and count for the 12-month period
	var totalAmount int64
	var totalCount int
	err := db.QueryRow(`
		SELECT COALESCE(SUM(amount), 0), COUNT(*)
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at <= $5
		AND deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total sales for 12 months: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for monthly breakdown
	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE_TRUNC('month', created_at), 'YYYY-MM-DD') as month_start,
			COALESCE(SUM(amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts
		WHERE account_id = $1
		AND state IN ($2, $3)
		AND created_at >= $4
		AND created_at <= $5
		AND deleted_at IS NULL
		GROUP BY DATE_TRUNC('month', created_at)
		ORDER BY month_start`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth)

	if err != nil {
		return nil, fmt.Errorf("error querying monthly sales: %w", err)
	}
	defer rows.Close()

	// Process query results directly into data points
	for rows.Next() {
		var monthStr string
		var amount int64
		var count int
		if err := rows.Scan(&monthStr, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning monthly sales row: %w", err)
		}

		// Parse the month string to a time.Time
		monthDate, err := time.Parse("2006-01-02", monthStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing month date: %w", err)
		}

		// Find the corresponding data point by comparing month and year
		for i := range summary.DataPoints {
			// Compare month and year for equality
			if summary.DataPoints[i].Month.Month() == monthDate.Month() &&
				summary.DataPoints[i].Month.Year() == monthDate.Year() {
				summary.DataPoints[i].Amount = amount
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through monthly sales rows: %w", err)
	}

	return summary, nil
}

// DashboardService provides business logic for dashboard operations
type DashboardService struct {
	repository *DashboardRepository
}

// NewDashboardService creates a new instance of DashboardService
func NewDashboardService() *DashboardService {
	return &DashboardService{
		repository: &DashboardRepository{},
	}
}

// GetSalesForDate retrieves sales data for a specific date
func (s *DashboardService) GetSalesForDate(accountID uuid.UUID, date time.Time) (*SalesSummary, error) {
	return s.repository.GetSalesForDate(accountID, date)
}

// GetSalesDateRange retrieves sales data for a custom date range
func (s *DashboardService) GetSalesDateRange(accountID uuid.UUID, startDate, endDate time.Time, groupBy string) (*SalesSummary, error) {
	return s.repository.GetSalesDateRange(accountID, startDate, endDate, groupBy)
}

// GetLast7DaysSales retrieves sales data for the last 7 days ending on the specified date
func (s *DashboardService) GetLast7DaysSales(accountID uuid.UUID, endDate time.Time) (*WeeklySalesSummary, error) {
	return s.repository.GetLast7DaysSales(accountID, endDate)
}

// GetLast30DaysSales retrieves sales data for the last 30 days ending on the specified date
func (s *DashboardService) GetLast30DaysSales(accountID uuid.UUID, endDate time.Time) (*WeeklySalesSummary, error) {
	return s.repository.GetLast30DaysSales(accountID, endDate)
}

// GetLast6MonthsSales retrieves sales data for the last 6 months ending on the specified date
func (s *DashboardService) GetLast6MonthsSales(accountID uuid.UUID, endDate time.Time) (*MonthlySalesSummary, error) {
	return s.repository.GetLast6MonthsSales(accountID, endDate)
}

// GetLast12MonthsSales retrieves sales data for the last 12 months ending on the specified date
func (s *DashboardService) GetLast12MonthsSales(accountID uuid.UUID, endDate time.Time) (*MonthlySalesSummary, error) {
	return s.repository.GetLast12MonthsSales(accountID, endDate)
}

// DashboardHandler handles HTTP requests for dashboard operations
type DashboardHandler struct{}

// Initialize a global instance of the dashboard service
var dashboardService = NewDashboardService()

// GetDailySales handles the request for a specific date's sales data
func (h *DashboardHandler) GetDailySales(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountID")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
		return
	}

	dateStr := chi.URLParam(r, "date")
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD", err.Error())
		return
	}

	// Check if user has access to this account
	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	// Check permissions
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	if account.UserID != user.ID {
		// Check if API key has access
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetSalesForDate(accountID, date)
	if err != nil {
		logger.Error("Error getting sales for date", "error", err, "account_id", accountID, "date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving sales data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Sales data for %s retrieved successfully", dateStr), summary)
}

// GetLast7DaysSales handles the request for the last 7 days' sales data
func (h *DashboardHandler) GetLast7DaysSales(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountID")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
		return
	}

	dateStr := chi.URLParam(r, "date")
	endDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD", err.Error())
		return
	}

	// Check if user has access to this account
	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	// Check permissions
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	if account.UserID != user.ID {
		// Check if API key has access
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast7DaysSales(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 7 days sales", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving sales data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 7 days sales data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast30DaysSales handles the request for the last 30 days' sales data
func (h *DashboardHandler) GetLast30DaysSales(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountID")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
		return
	}

	dateStr := chi.URLParam(r, "date")
	endDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD", err.Error())
		return
	}

	// Check if user has access to this account
	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	// Check permissions
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	if account.UserID != user.ID {
		// Check if API key has access
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast30DaysSales(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 30 days sales", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving sales data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 30 days sales data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast6MonthsSales handles the request for the last 6 months' sales data
func (h *DashboardHandler) GetLast6MonthsSales(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountID")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
		return
	}

	dateStr := chi.URLParam(r, "date")
	endDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD", err.Error())
		return
	}

	// Check if user has access to this account
	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	// Check permissions
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	if account.UserID != user.ID {
		// Check if API key has access
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast6MonthsSales(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 6 months sales", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving sales data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 6 months sales data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast12MonthsSales handles the request for the last 12 months' sales data
func (h *DashboardHandler) GetLast12MonthsSales(w http.ResponseWriter, r *http.Request) {
	accountIDStr := chi.URLParam(r, "accountID")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid account ID", err.Error())
		return
	}

	dateStr := chi.URLParam(r, "date")
	endDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		JsonResponse(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD", err.Error())
		return
	}

	// Check if user has access to this account
	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	// Check permissions
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		JsonResponse(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	if account.UserID != user.ID {
		// Check if API key has access
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast12MonthsSales(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 12 months sales", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving sales data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 12 months sales data ending on %s retrieved successfully", dateStr), summary)
}

// Setup global handler instance
var dashboardHandler = &DashboardHandler{}

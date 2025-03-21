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

// CustomerDataPoint represents a single data point for customer analytics
type CustomerDataPoint struct {
	Date       time.Time `json:"date"`
	Count      int       `json:"count"`
	DayOfWeek  int       `json:"day_of_week"`
	DayOfMonth int       `json:"day_of_month"`
	Month      int       `json:"month"`
	Year       int       `json:"year"`
}

// CustomerSummary represents a summary of new customers for a given period
type CustomerSummary struct {
	TotalCount int                 `json:"total_count"`
	StartDate  time.Time           `json:"start_date"`
	EndDate    time.Time           `json:"end_date"`
	DataPoints []CustomerDataPoint `json:"data_points"`
}

// SubscriberDataPoint represents a single data point for subscriber analytics
type SubscriberDataPoint struct {
	Date       time.Time `json:"date"`
	Count      int       `json:"count"`
	DayOfWeek  int       `json:"day_of_week"`
	DayOfMonth int       `json:"day_of_month"`
	Month      int       `json:"month"`
	Year       int       `json:"year"`
}

// SubscriberSummary represents a summary of active subscribers for a given period
type SubscriberSummary struct {
	TotalCount int                   `json:"total_count"`
	StartDate  time.Time             `json:"start_date"`
	EndDate    time.Time             `json:"end_date"`
	DataPoints []SubscriberDataPoint `json:"data_points"`
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

// GetLast7DaysNewCustomers retrieves new customers for the 7 days ending on the specified date
func (r *DashboardRepository) GetLast7DaysNewCustomers(accountID uuid.UUID, endDate time.Time) (*CustomerSummary, error) {
	endOfDay := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 999999999, time.UTC)
	startDate := endOfDay.AddDate(0, 0, -6)
	startOfPeriod := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)

	summary := &CustomerSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfDay,
		DataPoints: make([]CustomerDataPoint, 7),
	}

	for i := 0; i < 7; i++ {
		dayDate := startOfPeriod.AddDate(0, 0, i)
		summary.DataPoints[i] = CustomerDataPoint{
			Date:       dayDate,
			Count:      0,
			DayOfWeek:  int(dayDate.Weekday()),
			DayOfMonth: dayDate.Day(),
			Month:      int(dayDate.Month()),
			Year:       dayDate.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM customers
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at <= $3
		AND deleted_at IS NULL`,
		accountID, startOfPeriod, endOfDay).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total new customers for 7 days: %w", err)
	}

	summary.TotalCount = totalCount

	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE(created_at), 'YYYY-MM-DD') as creation_date,
			COUNT(*) as count
		FROM customers
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at <= $3
		AND deleted_at IS NULL
		GROUP BY DATE(created_at)
		ORDER BY creation_date`,
		accountID, startOfPeriod, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying daily new customers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dateStr string
		var count int
		if err := rows.Scan(&dateStr, &count); err != nil {
			return nil, fmt.Errorf("error scanning daily new customers row: %w", err)
		}

		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing date: %w", err)
		}

		for i := range summary.DataPoints {
			if summary.DataPoints[i].Date.Format("2006-01-02") == date.Format("2006-01-02") {
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through daily new customers rows: %w", err)
	}

	return summary, nil
}

// GetLast30DaysNewCustomers retrieves new customers for the 30 days ending on the specified date
func (r *DashboardRepository) GetLast30DaysNewCustomers(accountID uuid.UUID, endDate time.Time) (*CustomerSummary, error) {
	endOfDay := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 999999999, time.UTC)
	startDate := endOfDay.AddDate(0, 0, -29)
	startOfPeriod := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)

	summary := &CustomerSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfDay,
		DataPoints: make([]CustomerDataPoint, 30),
	}

	for i := 0; i < 30; i++ {
		dayDate := startOfPeriod.AddDate(0, 0, i)
		summary.DataPoints[i] = CustomerDataPoint{
			Date:       dayDate,
			Count:      0,
			DayOfWeek:  int(dayDate.Weekday()),
			DayOfMonth: dayDate.Day(),
			Month:      int(dayDate.Month()),
			Year:       dayDate.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM customers
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at <= $3
		AND deleted_at IS NULL`,
		accountID, startOfPeriod, endOfDay).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total new customers for 30 days: %w", err)
	}

	summary.TotalCount = totalCount

	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE(created_at), 'YYYY-MM-DD') as creation_date,
			COUNT(*) as count
		FROM customers
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at <= $3
		AND deleted_at IS NULL
		GROUP BY DATE(created_at)
		ORDER BY creation_date`,
		accountID, startOfPeriod, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying daily new customers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dateStr string
		var count int
		if err := rows.Scan(&dateStr, &count); err != nil {
			return nil, fmt.Errorf("error scanning daily new customers row: %w", err)
		}

		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing date: %w", err)
		}

		for i := range summary.DataPoints {
			if summary.DataPoints[i].Date.Format("2006-01-02") == date.Format("2006-01-02") {
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through daily new customers rows: %w", err)
	}

	return summary, nil
}

// GetLast6MonthsNewCustomers retrieves new customers for the 6 months ending on the specified date
func (r *DashboardRepository) GetLast6MonthsNewCustomers(accountID uuid.UUID, endDate time.Time) (*CustomerSummary, error) {
	endOfMonth := time.Date(endDate.Year(), endDate.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0).Add(-time.Nanosecond)
	startMonth := endOfMonth.AddDate(0, -5, 0)
	startOfPeriod := time.Date(startMonth.Year(), startMonth.Month(), 1, 0, 0, 0, 0, time.UTC)

	summary := &CustomerSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfMonth,
		DataPoints: make([]CustomerDataPoint, 6),
	}

	for i := 0; i < 6; i++ {
		monthDate := startOfPeriod.AddDate(0, i, 0)
		summary.DataPoints[i] = CustomerDataPoint{
			Date:       monthDate,
			Count:      0,
			DayOfWeek:  int(monthDate.Weekday()),
			DayOfMonth: monthDate.Day(),
			Month:      int(monthDate.Month()),
			Year:       monthDate.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM customers
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at <= $3
		AND deleted_at IS NULL`,
		accountID, startOfPeriod, endOfMonth).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total new customers for 6 months: %w", err)
	}

	summary.TotalCount = totalCount

	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE_TRUNC('month', c.created_at), 'YYYY-MM-DD') as month_start,
			COUNT(*) as count
		FROM customers c
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at <= $3
		AND deleted_at IS NULL
		GROUP BY DATE_TRUNC('month', c.created_at)
		ORDER BY month_start`,
		accountID, startOfPeriod, endOfMonth)

	if err != nil {
		return nil, fmt.Errorf("error querying monthly new customers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var monthStr string
		var count int
		if err := rows.Scan(&monthStr, &count); err != nil {
			return nil, fmt.Errorf("error scanning monthly new customers row: %w", err)
		}

		monthDate, err := time.Parse("2006-01-02", monthStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing month date: %w", err)
		}

		for i := range summary.DataPoints {
			if summary.DataPoints[i].Date.Month() == monthDate.Month() &&
				summary.DataPoints[i].Date.Year() == monthDate.Year() {
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through monthly new customers rows: %w", err)
	}

	return summary, nil
}

// GetLast12MonthsNewCustomers retrieves new customers for the 12 months ending on the specified date
func (r *DashboardRepository) GetLast12MonthsNewCustomers(accountID uuid.UUID, endDate time.Time) (*CustomerSummary, error) {
	endOfMonth := time.Date(endDate.Year(), endDate.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0).Add(-time.Nanosecond)
	startMonth := endOfMonth.AddDate(0, -11, 0)
	startOfPeriod := time.Date(startMonth.Year(), startMonth.Month(), 1, 0, 0, 0, 0, time.UTC)

	summary := &CustomerSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfMonth,
		DataPoints: make([]CustomerDataPoint, 12),
	}

	for i := 0; i < 12; i++ {
		monthDate := startOfPeriod.AddDate(0, i, 0)
		summary.DataPoints[i] = CustomerDataPoint{
			Date:       monthDate,
			Count:      0,
			DayOfWeek:  int(monthDate.Weekday()),
			DayOfMonth: monthDate.Day(),
			Month:      int(monthDate.Month()),
			Year:       monthDate.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM customers
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at <= $3
		AND deleted_at IS NULL`,
		accountID, startOfPeriod, endOfMonth).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total new customers for 12 months: %w", err)
	}

	summary.TotalCount = totalCount

	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE_TRUNC('month', c.created_at), 'YYYY-MM-DD') as month_start,
			COUNT(*) as count
		FROM customers c
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at <= $3
		AND deleted_at IS NULL
		GROUP BY DATE_TRUNC('month', c.created_at)
		ORDER BY month_start`,
		accountID, startOfPeriod, endOfMonth)

	if err != nil {
		return nil, fmt.Errorf("error querying monthly new customers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var monthStr string
		var count int
		if err := rows.Scan(&monthStr, &count); err != nil {
			return nil, fmt.Errorf("error scanning monthly new customers row: %w", err)
		}

		monthDate, err := time.Parse("2006-01-02", monthStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing month date: %w", err)
		}

		for i := range summary.DataPoints {
			if summary.DataPoints[i].Date.Month() == monthDate.Month() &&
				summary.DataPoints[i].Date.Year() == monthDate.Year() {
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through monthly new customers rows: %w", err)
	}

	return summary, nil
}

// GetCustomersForDate retrieves customer data for a specific date, grouped by hour
func (r *DashboardRepository) GetCustomersForDate(accountID uuid.UUID, date time.Time) (*CustomerSummary, error) {
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	summary := &CustomerSummary{
		StartDate:  startOfDay,
		EndDate:    endOfDay,
		DataPoints: make([]CustomerDataPoint, 24),
	}

	for i := 0; i < 24; i++ {
		hourTime := startOfDay.Add(time.Duration(i) * time.Hour)
		summary.DataPoints[i] = CustomerDataPoint{
			Date:       hourTime,
			Count:      0,
			DayOfWeek:  int(hourTime.Weekday()),
			DayOfMonth: hourTime.Day(),
			Month:      int(hourTime.Month()),
			Year:       hourTime.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM customers
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at < $3
		AND deleted_at IS NULL`,
		accountID, startOfDay, endOfDay).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total new customers for day: %w", err)
	}

	summary.TotalCount = totalCount

	// Explicitly extract hour in UTC to ensure consistency
	rows, err := db.Query(`
		SELECT 
			EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC') as hour,
			COUNT(*) as count
		FROM customers
		WHERE account_id = $1
		AND created_at >= $2
		AND created_at < $3
		AND deleted_at IS NULL
		GROUP BY EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC')
		ORDER BY hour`,
		accountID, startOfDay, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying hourly new customers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var hour int
		var count int
		if err := rows.Scan(&hour, &count); err != nil {
			return nil, fmt.Errorf("error scanning hourly new customers row: %w", err)
		}

		if hour >= 0 && hour < 24 {
			summary.DataPoints[hour].Count = count
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through hourly new customers rows: %w", err)
	}

	return summary, nil
}

// GetLast7DaysActiveSubscribers retrieves active subscribers for the 7 days ending on the specified date
func (r *DashboardRepository) GetLast7DaysActiveSubscribers(accountID uuid.UUID, endDate time.Time) (*SubscriberSummary, error) {
	endOfDay := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 999999999, time.UTC)
	startDate := endOfDay.AddDate(0, 0, -6)
	startOfPeriod := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)

	summary := &SubscriberSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfDay,
		DataPoints: make([]SubscriberDataPoint, 7),
	}

	for i := 0; i < 7; i++ {
		dayDate := startOfPeriod.AddDate(0, 0, i)
		summary.DataPoints[i] = SubscriberDataPoint{
			Date:       dayDate,
			Count:      0,
			DayOfWeek:  int(dayDate.Weekday()),
			DayOfMonth: dayDate.Day(),
			Month:      int(dayDate.Month()),
			Year:       dayDate.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(DISTINCT c.customer_id)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total active subscribers for 7 days: %w", err)
	}

	summary.TotalCount = totalCount

	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE(c.created_at), 'YYYY-MM-DD') as subscription_date,
			COUNT(DISTINCT c.customer_id) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL
		GROUP BY DATE(c.created_at)
		ORDER BY subscription_date`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying daily active subscribers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dateStr string
		var count int
		if err := rows.Scan(&dateStr, &count); err != nil {
			return nil, fmt.Errorf("error scanning daily active subscribers row: %w", err)
		}

		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing date: %w", err)
		}

		for i := range summary.DataPoints {
			if summary.DataPoints[i].Date.Format("2006-01-02") == date.Format("2006-01-02") {
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through daily active subscribers rows: %w", err)
	}

	return summary, nil
}

// GetLast30DaysActiveSubscribers retrieves active subscribers for the 30 days ending on the specified date
func (r *DashboardRepository) GetLast30DaysActiveSubscribers(accountID uuid.UUID, endDate time.Time) (*SubscriberSummary, error) {
	endOfDay := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 999999999, time.UTC)
	startDate := endOfDay.AddDate(0, 0, -29)
	startOfPeriod := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)

	summary := &SubscriberSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfDay,
		DataPoints: make([]SubscriberDataPoint, 30),
	}

	for i := 0; i < 30; i++ {
		dayDate := startOfPeriod.AddDate(0, 0, i)
		summary.DataPoints[i] = SubscriberDataPoint{
			Date:       dayDate,
			Count:      0,
			DayOfWeek:  int(dayDate.Weekday()),
			DayOfMonth: dayDate.Day(),
			Month:      int(dayDate.Month()),
			Year:       dayDate.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(DISTINCT c.customer_id)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total active subscribers for 30 days: %w", err)
	}

	summary.TotalCount = totalCount

	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE(c.created_at), 'YYYY-MM-DD') as subscription_date,
			COUNT(DISTINCT c.customer_id) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL
		GROUP BY DATE(c.created_at)
		ORDER BY subscription_date`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying daily active subscribers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dateStr string
		var count int
		if err := rows.Scan(&dateStr, &count); err != nil {
			return nil, fmt.Errorf("error scanning daily active subscribers row: %w", err)
		}

		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing date: %w", err)
		}

		for i := range summary.DataPoints {
			if summary.DataPoints[i].Date.Format("2006-01-02") == date.Format("2006-01-02") {
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through daily active subscribers rows: %w", err)
	}

	return summary, nil
}

// GetLast6MonthsActiveSubscribers handles the request for the last 6 months' active subscriber data
func (r *DashboardRepository) GetLast6MonthsActiveSubscribers(accountID uuid.UUID, endDate time.Time) (*SubscriberSummary, error) {
	endOfMonth := time.Date(endDate.Year(), endDate.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0).Add(-time.Nanosecond)
	startMonth := endOfMonth.AddDate(0, -5, 0)
	startOfPeriod := time.Date(startMonth.Year(), startMonth.Month(), 1, 0, 0, 0, 0, time.UTC)

	summary := &SubscriberSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfMonth,
		DataPoints: make([]SubscriberDataPoint, 6),
	}

	for i := 0; i < 6; i++ {
		monthDate := startOfPeriod.AddDate(0, i, 0)
		summary.DataPoints[i] = SubscriberDataPoint{
			Date:       monthDate,
			Count:      0,
			DayOfWeek:  int(monthDate.Weekday()),
			DayOfMonth: monthDate.Day(),
			Month:      int(monthDate.Month()),
			Year:       monthDate.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(DISTINCT c.customer_id)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total active subscribers for 6 months: %w", err)
	}

	summary.TotalCount = totalCount

	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE_TRUNC('month', c.created_at), 'YYYY-MM-DD') as month_start,
			COUNT(DISTINCT c.customer_id) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL
		GROUP BY DATE_TRUNC('month', c.created_at)
		ORDER BY month_start`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth)

	if err != nil {
		return nil, fmt.Errorf("error querying monthly active subscribers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var monthStr string
		var count int
		if err := rows.Scan(&monthStr, &count); err != nil {
			return nil, fmt.Errorf("error scanning monthly active subscribers row: %w", err)
		}

		monthDate, err := time.Parse("2006-01-02", monthStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing month date: %w", err)
		}

		for i := range summary.DataPoints {
			if summary.DataPoints[i].Date.Month() == monthDate.Month() &&
				summary.DataPoints[i].Date.Year() == monthDate.Year() {
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through monthly active subscribers rows: %w", err)
	}

	return summary, nil
}

// GetLast12MonthsActiveSubscribers handles the request for the last 12 months' active subscriber data
func (r *DashboardRepository) GetLast12MonthsActiveSubscribers(accountID uuid.UUID, endDate time.Time) (*SubscriberSummary, error) {
	endOfMonth := time.Date(endDate.Year(), endDate.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0).Add(-time.Nanosecond)
	startMonth := endOfMonth.AddDate(0, -11, 0)
	startOfPeriod := time.Date(startMonth.Year(), startMonth.Month(), 1, 0, 0, 0, 0, time.UTC)

	summary := &SubscriberSummary{
		StartDate:  startOfPeriod,
		EndDate:    endOfMonth,
		DataPoints: make([]SubscriberDataPoint, 12),
	}

	for i := 0; i < 12; i++ {
		monthDate := startOfPeriod.AddDate(0, i, 0)
		summary.DataPoints[i] = SubscriberDataPoint{
			Date:       monthDate,
			Count:      0,
			DayOfWeek:  int(monthDate.Weekday()),
			DayOfMonth: monthDate.Day(),
			Month:      int(monthDate.Month()),
			Year:       monthDate.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(DISTINCT c.customer_id)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total active subscribers for 12 months: %w", err)
	}

	summary.TotalCount = totalCount

	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE_TRUNC('month', c.created_at), 'YYYY-MM-DD') as month_start,
			COUNT(DISTINCT c.customer_id) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL
		GROUP BY DATE_TRUNC('month', c.created_at)
		ORDER BY month_start`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth)

	if err != nil {
		return nil, fmt.Errorf("error querying monthly active subscribers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var monthStr string
		var count int
		if err := rows.Scan(&monthStr, &count); err != nil {
			return nil, fmt.Errorf("error scanning monthly active subscribers row: %w", err)
		}

		monthDate, err := time.Parse("2006-01-02", monthStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing month date: %w", err)
		}

		for i := range summary.DataPoints {
			if summary.DataPoints[i].Date.Month() == monthDate.Month() &&
				summary.DataPoints[i].Date.Year() == monthDate.Year() {
				summary.DataPoints[i].Count = count
				break
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through monthly active subscribers rows: %w", err)
	}

	return summary, nil
}

// GetActiveSubscribersForDate retrieves active subscriber data for a specific date, grouped by hour
func (r *DashboardRepository) GetActiveSubscribersForDate(accountID uuid.UUID, date time.Time) (*SubscriberSummary, error) {
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	summary := &SubscriberSummary{
		StartDate:  startOfDay,
		EndDate:    endOfDay,
		DataPoints: make([]SubscriberDataPoint, 24),
	}

	for i := 0; i < 24; i++ {
		hourTime := startOfDay.Add(time.Duration(i) * time.Hour)
		summary.DataPoints[i] = SubscriberDataPoint{
			Date:       hourTime,
			Count:      0,
			DayOfWeek:  int(hourTime.Weekday()),
			DayOfMonth: hourTime.Day(),
			Month:      int(hourTime.Month()),
			Year:       hourTime.Year(),
		}
	}

	var totalCount int
	err := db.QueryRow(`
		SELECT COUNT(DISTINCT c.customer_id)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at < $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfDay, endOfDay).
		Scan(&totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total active subscribers for day: %w", err)
	}

	summary.TotalCount = totalCount

	// Explicitly extract hour in UTC to ensure consistency
	rows, err := db.Query(`
		SELECT 
			EXTRACT(HOUR FROM c.created_at AT TIME ZONE 'UTC') as hour,
			COUNT(DISTINCT c.customer_id) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at < $5
		AND c.customer_id IS NOT NULL
		AND c.deleted_at IS NULL
		GROUP BY EXTRACT(HOUR FROM c.created_at AT TIME ZONE 'UTC')
		ORDER BY hour`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfDay, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying hourly active subscribers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var hour int
		var count int
		if err := rows.Scan(&hour, &count); err != nil {
			return nil, fmt.Errorf("error scanning hourly active subscribers row: %w", err)
		}

		if hour >= 0 && hour < 24 {
			summary.DataPoints[hour].Count = count
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through hourly active subscribers rows: %w", err)
	}

	return summary, nil
}

// GetLast7DaysMRR retrieves MRR data for the 7 days ending on the specified date
func (r *DashboardRepository) GetLast7DaysMRR(accountID uuid.UUID, endDate time.Time) (*WeeklySalesSummary, error) {
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
		SELECT COALESCE(SUM(c.amount), 0), COUNT(*)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total MRR for 7 days: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for daily breakdown - use TO_CHAR to format the date properly
	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE(c.created_at), 'YYYY-MM-DD') as sale_date,
			COALESCE(SUM(c.amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.deleted_at IS NULL
		GROUP BY DATE(c.created_at)
		ORDER BY sale_date`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying daily MRR: %w", err)
	}
	defer rows.Close()

	// Process query results directly into data points
	for rows.Next() {
		var dateStr string
		var amount int64
		var count int
		if err := rows.Scan(&dateStr, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning daily MRR row: %w", err)
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
		return nil, fmt.Errorf("error iterating through daily MRR rows: %w", err)
	}

	return summary, nil
}

// GetLast30DaysMRR retrieves MRR data for the 30 days ending on the specified date
func (r *DashboardRepository) GetLast30DaysMRR(accountID uuid.UUID, endDate time.Time) (*WeeklySalesSummary, error) {
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
		SELECT COALESCE(SUM(c.amount), 0), COUNT(*)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total MRR for 30 days: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for daily breakdown
	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE(c.created_at), 'YYYY-MM-DD') as sale_date,
			COALESCE(SUM(c.amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.deleted_at IS NULL
		GROUP BY DATE(c.created_at)
		ORDER BY sale_date`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying daily MRR: %w", err)
	}
	defer rows.Close()

	// Process query results directly into data points
	for rows.Next() {
		var dateStr string
		var amount int64
		var count int
		if err := rows.Scan(&dateStr, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning daily MRR row: %w", err)
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
		return nil, fmt.Errorf("error iterating through daily MRR rows: %w", err)
	}

	return summary, nil
}

// GetLast6MonthsMRR retrieves MRR data for the 6 months ending on the specified date
func (r *DashboardRepository) GetLast6MonthsMRR(accountID uuid.UUID, endDate time.Time) (*MonthlySalesSummary, error) {
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
		SELECT COALESCE(SUM(c.amount), 0), COUNT(*)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total MRR for 6 months: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for monthly breakdown
	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE_TRUNC('month', c.created_at), 'YYYY-MM-DD') as month_start,
			COALESCE(SUM(c.amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.deleted_at IS NULL
		GROUP BY DATE_TRUNC('month', c.created_at)
		ORDER BY month_start`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth)

	if err != nil {
		return nil, fmt.Errorf("error querying monthly MRR: %w", err)
	}
	defer rows.Close()

	// Process query results directly into data points
	for rows.Next() {
		var monthStr string
		var amount int64
		var count int
		if err := rows.Scan(&monthStr, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning monthly MRR row: %w", err)
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
		return nil, fmt.Errorf("error iterating through monthly MRR rows: %w", err)
	}

	return summary, nil
}

// GetLast12MonthsMRR retrieves MRR data for the 12 months ending on the specified date
func (r *DashboardRepository) GetLast12MonthsMRR(accountID uuid.UUID, endDate time.Time) (*MonthlySalesSummary, error) {
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
		SELECT COALESCE(SUM(c.amount), 0), COUNT(*)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total MRR for 12 months: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for monthly breakdown
	rows, err := db.Query(`
		SELECT 
			TO_CHAR(DATE_TRUNC('month', c.created_at), 'YYYY-MM-DD') as month_start,
			COALESCE(SUM(c.amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at <= $5
		AND c.deleted_at IS NULL
		GROUP BY DATE_TRUNC('month', c.created_at)
		ORDER BY month_start`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfPeriod, endOfMonth)

	if err != nil {
		return nil, fmt.Errorf("error querying monthly MRR: %w", err)
	}
	defer rows.Close()

	// Process query results directly into data points
	for rows.Next() {
		var monthStr string
		var amount int64
		var count int
		if err := rows.Scan(&monthStr, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning monthly MRR row: %w", err)
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
		return nil, fmt.Errorf("error iterating through monthly MRR rows: %w", err)
	}

	return summary, nil
}

// GetMRRForDate retrieves MRR data for a specific date, grouped by hour
func (r *DashboardRepository) GetMRRForDate(accountID uuid.UUID, date time.Time) (*SalesSummary, error) {
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
		SELECT COALESCE(SUM(c.amount), 0), COUNT(*)
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at < $5
		AND c.deleted_at IS NULL`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfDay, endOfDay).
		Scan(&totalAmount, &totalCount)

	if err != nil {
		return nil, fmt.Errorf("error querying total MRR: %w", err)
	}

	summary.TotalAmount = totalAmount
	summary.TotalCount = totalCount

	// Query for hourly breakdown
	rows, err := db.Query(`
		SELECT 
			EXTRACT(HOUR FROM c.created_at) as hour,
			COALESCE(SUM(c.amount), 0) as amount,
			COUNT(*) as count
		FROM checkouts c
		JOIN products p ON c.product_id = p.id
		WHERE c.account_id = $1
		AND p.is_recurring = true
		AND c.state IN ($2, $3)
		AND c.created_at >= $4
		AND c.created_at < $5
		AND c.deleted_at IS NULL
		GROUP BY EXTRACT(HOUR FROM c.created_at)
		ORDER BY hour`,
		accountID, CheckoutStatePaid, CheckoutStateOverpaid, startOfDay, endOfDay)

	if err != nil {
		return nil, fmt.Errorf("error querying hourly MRR: %w", err)
	}
	defer rows.Close()

	// Populate hourly data
	for rows.Next() {
		var hour int
		var amount int64
		var count int
		if err := rows.Scan(&hour, &amount, &count); err != nil {
			return nil, fmt.Errorf("error scanning hourly MRR row: %w", err)
		}

		if hour >= 0 && hour < 24 {
			summary.DataPoints[hour].Amount = amount
			summary.DataPoints[hour].Count = count
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through hourly MRR rows: %w", err)
	}

	return summary, nil
}

// GetMRRToday retrieves MRR data for today, grouped by hour
func (r *DashboardRepository) GetMRRToday(accountID uuid.UUID) (*SalesSummary, error) {
	// Reuse the GetMRRForDate method with today's date
	return r.GetMRRForDate(accountID, time.Now().UTC())
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

// GetLast7DaysMRR retrieves MRR data for the 7 days ending on the specified date
func (s *DashboardService) GetLast7DaysMRR(accountID uuid.UUID, endDate time.Time) (*WeeklySalesSummary, error) {
	return s.repository.GetLast7DaysMRR(accountID, endDate)
}

// GetLast30DaysMRR retrieves MRR data for the 30 days ending on the specified date
func (s *DashboardService) GetLast30DaysMRR(accountID uuid.UUID, endDate time.Time) (*WeeklySalesSummary, error) {
	return s.repository.GetLast30DaysMRR(accountID, endDate)
}

// GetLast6MonthsMRR retrieves MRR data for the 6 months ending on the specified date
func (s *DashboardService) GetLast6MonthsMRR(accountID uuid.UUID, endDate time.Time) (*MonthlySalesSummary, error) {
	return s.repository.GetLast6MonthsMRR(accountID, endDate)
}

// GetLast12MonthsMRR retrieves MRR data for the 12 months ending on the specified date
func (s *DashboardService) GetLast12MonthsMRR(accountID uuid.UUID, endDate time.Time) (*MonthlySalesSummary, error) {
	return s.repository.GetLast12MonthsMRR(accountID, endDate)
}

// GetMRRForDate retrieves MRR data for a specific date, grouped by hour
func (s *DashboardService) GetMRRForDate(accountID uuid.UUID, date time.Time) (*SalesSummary, error) {
	return s.repository.GetMRRForDate(accountID, date)
}

// GetMRRToday retrieves MRR data for today, grouped by hour
func (s *DashboardService) GetMRRToday(accountID uuid.UUID) (*SalesSummary, error) {
	return s.repository.GetMRRToday(accountID)
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

// GetLast7DaysNewCustomers retrieves new customer data for the last 7 days ending on the specified date
func (s *DashboardService) GetLast7DaysNewCustomers(accountID uuid.UUID, endDate time.Time) (*CustomerSummary, error) {
	return s.repository.GetLast7DaysNewCustomers(accountID, endDate)
}

// GetLast30DaysNewCustomers retrieves new customer data for the last 30 days ending on the specified date
func (s *DashboardService) GetLast30DaysNewCustomers(accountID uuid.UUID, endDate time.Time) (*CustomerSummary, error) {
	return s.repository.GetLast30DaysNewCustomers(accountID, endDate)
}

// GetLast6MonthsNewCustomers retrieves new customers for the 6 months ending on the specified date
func (s *DashboardService) GetLast6MonthsNewCustomers(accountID uuid.UUID, endDate time.Time) (*CustomerSummary, error) {
	return s.repository.GetLast6MonthsNewCustomers(accountID, endDate)
}

// GetLast12MonthsNewCustomers retrieves new customers for the 12 months ending on the specified date
func (s *DashboardService) GetLast12MonthsNewCustomers(accountID uuid.UUID, endDate time.Time) (*CustomerSummary, error) {
	return s.repository.GetLast12MonthsNewCustomers(accountID, endDate)
}

// GetCustomersForDate retrieves customer data for a specific date, grouped by hour
func (s *DashboardService) GetCustomersForDate(accountID uuid.UUID, date time.Time) (*CustomerSummary, error) {
	return s.repository.GetCustomersForDate(accountID, date)
}

// GetLast7DaysActiveSubscribers retrieves active subscribers for the 7 days ending on the specified date
func (s *DashboardService) GetLast7DaysActiveSubscribers(accountID uuid.UUID, endDate time.Time) (*SubscriberSummary, error) {
	return s.repository.GetLast7DaysActiveSubscribers(accountID, endDate)
}

// GetLast30DaysActiveSubscribers retrieves active subscribers for the 30 days ending on the specified date
func (s *DashboardService) GetLast30DaysActiveSubscribers(accountID uuid.UUID, endDate time.Time) (*SubscriberSummary, error) {
	return s.repository.GetLast30DaysActiveSubscribers(accountID, endDate)
}

// GetLast6MonthsActiveSubscribers handles the request for the last 6 months' active subscriber data
func (s *DashboardService) GetLast6MonthsActiveSubscribers(accountID uuid.UUID, endDate time.Time) (*SubscriberSummary, error) {
	return s.repository.GetLast6MonthsActiveSubscribers(accountID, endDate)
}

// GetLast12MonthsActiveSubscribers handles the request for the last 12 months' active subscriber data
func (s *DashboardService) GetLast12MonthsActiveSubscribers(accountID uuid.UUID, endDate time.Time) (*SubscriberSummary, error) {
	return s.repository.GetLast12MonthsActiveSubscribers(accountID, endDate)
}

// GetActiveSubscribersForDate retrieves active subscriber data for a specific date
func (s *DashboardService) GetActiveSubscribersForDate(accountID uuid.UUID, date time.Time) (*SubscriberSummary, error) {
	return s.repository.GetActiveSubscribersForDate(accountID, date)
}

// GetDailyActiveSubscribers handles the request for a specific date's active subscriber data
func (h *DashboardHandler) GetDailyActiveSubscribers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetActiveSubscribersForDate(accountID, date)
	if err != nil {
		logger.Error("Error getting daily active subscribers", "error", err, "account_id", accountID, "date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving active subscriber data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Active subscriber data for %s retrieved successfully", dateStr), summary)
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

	// Check if request is using API key
	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		// API key exists, check permissions
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		// Get account from API key and check if it matches the requested account
		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		// No API key, check user permissions
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user owns the account
		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	// Rest of handler code remains the same
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

	// Check if request is using API key
	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		// API key exists, check permissions
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		// Get account from API key and check if it matches the requested account
		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		// No API key, check user permissions
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user owns the account
		if account.UserID != user.ID {
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

	// Check if request is using API key
	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		// API key exists, check permissions
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		// Get account from API key and check if it matches the requested account
		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		// No API key, check user permissions
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user owns the account
		if account.UserID != user.ID {
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

	// Check if request is using API key
	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		// API key exists, check permissions
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		// Get account from API key and check if it matches the requested account
		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		// No API key, check user permissions
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user owns the account
		if account.UserID != user.ID {
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

	// Check if request is using API key
	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		// API key exists, check permissions
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		// Get account from API key and check if it matches the requested account
		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		// No API key, check user permissions
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Check if user owns the account
		if account.UserID != user.ID {
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

// GetLast7DaysNewCustomers handles the request for the last 7 days' new customer data
func (h *DashboardHandler) GetLast7DaysNewCustomers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast7DaysNewCustomers(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 7 days new customers", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving new customer data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 7 days new customer data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast30DaysNewCustomers handles the request for the last 30 days' new customer data
func (h *DashboardHandler) GetLast30DaysNewCustomers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast30DaysNewCustomers(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 30 days new customers", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving new customer data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 30 days new customer data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast6MonthsNewCustomers handles the request for the last 6 months' new customer data
func (h *DashboardHandler) GetLast6MonthsNewCustomers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast6MonthsNewCustomers(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 6 months new customers", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving new customer data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 6 months new customer data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast12MonthsNewCustomers handles the request for the last 12 months' new customer data
func (h *DashboardHandler) GetLast12MonthsNewCustomers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast12MonthsNewCustomers(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 12 months new customers", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving new customer data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 12 months new customer data ending on %s retrieved successfully", dateStr), summary)
}

// GetDailyCustomers handles the request for a specific date's new customer data
func (h *DashboardHandler) GetDailyCustomers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetCustomersForDate(accountID, date)
	if err != nil {
		logger.Error("Error getting daily new customers", "error", err, "account_id", accountID, "date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving new customer data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("New customer data for %s retrieved successfully", dateStr), summary)
}

// GetLast7DaysActiveSubscribers handles the request for the last 7 days' active subscriber data
func (h *DashboardHandler) GetLast7DaysActiveSubscribers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast7DaysActiveSubscribers(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 7 days active subscribers", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving active subscriber data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 7 days active subscriber data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast30DaysActiveSubscribers handles the request for the last 30 days' active subscriber data
func (h *DashboardHandler) GetLast30DaysActiveSubscribers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast30DaysActiveSubscribers(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 30 days active subscribers", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving active subscriber data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 30 days active subscriber data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast6MonthsActiveSubscribers handles the request for the last 6 months' active subscriber data
func (h *DashboardHandler) GetLast6MonthsActiveSubscribers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast6MonthsActiveSubscribers(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 6 months active subscribers", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving active subscriber data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 6 months active subscriber data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast12MonthsActiveSubscribers handles the request for the last 12 months' active subscriber data
func (h *DashboardHandler) GetLast12MonthsActiveSubscribers(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast12MonthsActiveSubscribers(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 12 months active subscribers", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving active subscriber data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 12 months active subscriber data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast7DaysMRR handles the request for the last 7 days' MRR data
func (h *DashboardHandler) GetLast7DaysMRR(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast7DaysMRR(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 7 days MRR", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving MRR data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 7 days MRR data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast30DaysMRR handles the request for the last 30 days' MRR data
func (h *DashboardHandler) GetLast30DaysMRR(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast30DaysMRR(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 30 days MRR", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving MRR data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 30 days MRR data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast6MonthsMRR handles the request for the last 6 months' MRR data
func (h *DashboardHandler) GetLast6MonthsMRR(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast6MonthsMRR(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 6 months MRR", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving MRR data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 6 months MRR data ending on %s retrieved successfully", dateStr), summary)
}

// GetLast12MonthsMRR handles the request for the last 12 months' MRR data
func (h *DashboardHandler) GetLast12MonthsMRR(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetLast12MonthsMRR(accountID, endDate)
	if err != nil {
		logger.Error("Error getting last 12 months MRR", "error", err, "account_id", accountID, "end_date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving MRR data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Last 12 months MRR data ending on %s retrieved successfully", dateStr), summary)
}

// GetDailyMRR handles the request for a specific date's MRR data
func (h *DashboardHandler) GetDailyMRR(w http.ResponseWriter, r *http.Request) {
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

	account, err := accountService.Get(accountID)
	if err != nil {
		JsonResponse(w, http.StatusNotFound, "Account not found", err.Error())
		return
	}

	_, apiKeyErr := GetAPIKeyFromContext(r.Context())
	if apiKeyErr == nil {
		if !CheckAPIPermission(r.Context(), "dashboard", "read") {
			JsonResponse(w, http.StatusForbidden, "API key doesn't have permission to access dashboard", nil)
			return
		}

		apiKeyAccount, err := GetAccountFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusInternalServerError, "Error retrieving account from API key", err.Error())
			return
		}

		if apiKeyAccount.ID != accountID {
			JsonResponse(w, http.StatusForbidden, "This account doesn't belong to the API key", nil)
			return
		}
	} else {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		if account.UserID != user.ID {
			JsonResponse(w, http.StatusForbidden, "Not authorized to access this account's dashboard", nil)
			return
		}
	}

	summary, err := dashboardService.GetMRRForDate(accountID, date)
	if err != nil {
		logger.Error("Error getting daily MRR", "error", err, "account_id", accountID, "date", dateStr)
		JsonResponse(w, http.StatusInternalServerError, "Error retrieving MRR data", err.Error())
		return
	}

	JsonResponse(w, http.StatusOK, fmt.Sprintf("Daily MRR data for %s retrieved successfully", dateStr), summary)
}

// Setup global handler instance
var dashboardHandler = &DashboardHandler{}

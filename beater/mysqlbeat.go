package beater

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"

	"github.com/adibendahan/mysqlbeat/config"

	// mysql go driver
	_ "github.com/go-sql-driver/mysql"
)

type Mysqlbeat struct {
	hostname         string
	port             string
	username         string
	password         string
	passwordAES      string
	queries          []string
	queryTypes       []string
	deltaWildcard    string
	deltaKeyWildcard string

	oldValues    common.MapStr
	oldValuesAge common.MapStr

	done   chan struct{}
	config config.Config
	client publisher.Client
}

var (
	commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
)

const (
	// secret length must be 16, 24 or 32, corresponding to the AES-128, AES-192 or AES-256 algorithms
	// you should compile your mysqlbeat with a unique secret and hide it (don't leave it in the code after compiled)
	// you can encrypt your password with github.com/adibendahan/mysqlbeat-password-encrypter just update your secret
	// (and commonIV if you choose to change it) and compile.
	secret = "github.com/adibendahan/mysqlbeat"

	// query types values
	queryTypeSingleRow    = "single-row"
	queryTypeMultipleRows = "multiple-rows"
	queryTypeTwoColumns   = "two-columns"
	queryTypeSlaveDelay   = "show-slave-delay"

	// special column names values
	columnNameSlaveDelay = "Seconds_Behind_Master"

	// column types values
	columnTypeString = iota
	columnTypeInt
	columnTypeFloat
)

// Creates beater
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config := config.DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Mysqlbeat{
		done:   make(chan struct{}),
		config: config,
	}

	// Handle password decryption and save in the bt
	if bt.config.EncryptedPassword != "" {
		aesCipher, err := aes.NewCipher([]byte(secret))
		if err != nil {
			return nil, err
		}
		cfbDecrypter := cipher.NewCFBDecrypter(aesCipher, commonIV)
		chiperText, err := hex.DecodeString(bt.config.EncryptedPassword)
		if err != nil {
			return nil, err
		}
		plaintextCopy := make([]byte, len(chiperText))
		cfbDecrypter.XORKeyStream(plaintextCopy, chiperText)
		bt.password = string(plaintextCopy)
	} else {
		bt.password = bt.config.Password
	}

	// init the oldValues and oldValuesAge array
	bt.oldValues = common.MapStr{"mysqlbeat": "init"}
	bt.oldValuesAge = common.MapStr{"mysqlbeat": "init"}

	// Save config values to the bt
	bt.hostname = bt.config.Hostname
	bt.port = bt.config.Port
	bt.username = bt.config.Username
	bt.queries = bt.config.Queries
	bt.queryTypes = bt.config.QueryTypes
	bt.deltaWildcard = bt.config.DeltaWildcard
	bt.deltaKeyWildcard = bt.config.DeltaKeyWildcard

	safeQueries := true

	logp.Info("Total # of queries to execute: %d", len(bt.queries))
	for index, queryStr := range bt.queries {

		strCleanQuery := strings.TrimSpace(strings.ToUpper(queryStr))

		if !strings.HasPrefix(strCleanQuery, "SELECT") && !strings.HasPrefix(strCleanQuery, "SHOW") || strings.ContainsAny(strCleanQuery, ";") {
			safeQueries = false
		}

		logp.Info("Query #%d (type: %s): %s", index+1, bt.queryTypes[index], queryStr)
	}

	if !safeQueries {
		err := fmt.Errorf("Only SELECT/SHOW queries are allowed (the char ; is forbidden)")
		return nil, err
	}

	return bt, nil
}

func (bt *Mysqlbeat) Run(b *beat.Beat) error {
	logp.Info("mysqlbeat is running! Hit CTRL-C to stop it.")

	bt.client = b.Publisher.Connect()
	ticker := time.NewTicker(bt.config.Period)
	for {
		select {
		case <-bt.done:
			return nil
		case <-ticker.C:
		}

		err := bt.beat(b)
		if err != nil {
			return err
		}
	}
}

func (bt *Mysqlbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}

///*** mysqlbeat methods ***///

// beat is a function that iterate over the query array, generate and publish events
func (bt *Mysqlbeat) beat(b *beat.Beat) error {

	// Build the MySQL connection string
	connString := fmt.Sprintf("%v:%v@tcp(%v:%v)/", bt.username, bt.password, bt.hostname, bt.port)

	db, err := sql.Open("mysql", connString)
	if err != nil {
		return err
	}
	defer db.Close()

	// Create a two-columns event for later use
	var twoColumnEvent common.MapStr

LoopQueries:
	for index, queryStr := range bt.queries {
		// Log the query run time and run the query
		dtNow := time.Now()
		rows, err := db.Query(queryStr)
		if err != nil {
			return err
		}

		// Populate columns array
		columns, err := rows.Columns()
		if err != nil {
			return err
		}

		// Populate the two-columns event
		if bt.queryTypes[index] == queryTypeTwoColumns {
			twoColumnEvent = common.MapStr{
				"@timestamp": common.Time(dtNow),
				"type":       queryTypeTwoColumns,
			}
		}

	LoopRows:
		for rows.Next() {

			switch bt.queryTypes[index] {
			case queryTypeSingleRow, queryTypeSlaveDelay:
				// Generate an event from the current row
				event, err := bt.generateEventFromRow(rows, columns, bt.queryTypes[index], dtNow)

				if err != nil {
					logp.Err("Query #%v error generating event from rows: %v", index+1, err)
				} else if event != nil {
					bt.client.PublishEvent(event)
					logp.Info("%v event sent", bt.queryTypes[index])
				}
				// breaking after the first row
				break LoopRows

			case queryTypeMultipleRows:
				// Generate an event from the current row
				event, err := bt.generateEventFromRow(rows, columns, bt.queryTypes[index], dtNow)

				if err != nil {
					logp.Err("Query #%v error generating event from rows: %v", index+1, err)
					break LoopRows
				} else if event != nil {
					bt.client.PublishEvent(event)
					logp.Info("%v event sent", bt.queryTypes[index])
				}

				// Move to the next row
				continue LoopRows

			case queryTypeTwoColumns:
				// append current row to the two-columns event
				err := bt.appendRowToEvent(twoColumnEvent, rows, columns, dtNow)

				if err != nil {
					logp.Err("Query #%v error appending two-columns event: %v", index+1, err)
					break LoopRows
				}

				// Move to the next row
				continue LoopRows
			}
		}

		// If the two-columns event has data, publish it
		if bt.queryTypes[index] == queryTypeTwoColumns && len(twoColumnEvent) > 2 {
			bt.client.PublishEvent(twoColumnEvent)
			logp.Info("%v event sent", queryTypeTwoColumns)
			twoColumnEvent = nil
		}

		rows.Close()
		if err = rows.Err(); err != nil {
			logp.Err("Query #%v error closing rows: %v", index+1, err)
			continue LoopQueries
		}
	}

	// Great success!
	return nil
}

// appendRowToEvent appends the two-column event the current row data
func (bt *Mysqlbeat) appendRowToEvent(event common.MapStr, row *sql.Rows, columns []string, rowAge time.Time) error {

	// Make a slice for the values
	values := make([]sql.RawBytes, len(columns))

	// Copy the references into such a []interface{} for row.Scan
	scanArgs := make([]interface{}, len(values))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	// Get RawBytes from data
	err := row.Scan(scanArgs...)
	if err != nil {
		return err
	}

	// First column is the name, second is the value
	strColName := string(values[0])
	strColValue := string(values[1])
	strColType := columnTypeString
	strEventColName := strings.Replace(strColName, bt.deltaWildcard, "_PERSECOND", 1)

	// Try to parse the value to an int64
	nColValue, err := strconv.ParseInt(strColValue, 0, 64)
	if err == nil {
		strColType = columnTypeInt
	}

	// Try to parse the value to a float64
	fColValue, err := strconv.ParseFloat(strColValue, 64)
	if err == nil {
		// If it's not already an established int64, set type to float
		if strColType == columnTypeString {
			strColType = columnTypeFloat
		}
	}

	// If the column name ends with the deltaWildcard
	if strings.HasSuffix(strColName, bt.deltaWildcard) {
		var exists bool
		_, exists = bt.oldValues[strColName]

		// If an older value doesn't exist
		if !exists {
			// Save the current value in the oldValues array
			bt.oldValuesAge[strColName] = rowAge

			if strColType == columnTypeString {
				bt.oldValues[strColName] = strColValue
			} else if strColType == columnTypeInt {
				bt.oldValues[strColName] = nColValue
			} else if strColType == columnTypeFloat {
				bt.oldValues[strColName] = fColValue
			}
		} else {
			// If found the old value's age
			if dtOldAge, ok := bt.oldValuesAge[strColName].(time.Time); ok {
				delta := rowAge.Sub(dtOldAge)

				if strColType == columnTypeInt {
					var calcVal int64

					// Get old value
					oldVal, _ := bt.oldValues[strColName].(int64)
					if nColValue > oldVal {
						// Calculate the delta
						devResult := float64((nColValue - oldVal)) / float64(delta.Seconds())
						// Round the calculated result back to an int64
						calcVal = roundF2I(devResult, .5)
					} else {
						calcVal = 0
					}

					// Add the delta value to the event
					event[strEventColName] = calcVal

					// Save current values as old values
					bt.oldValues[strColName] = nColValue
					bt.oldValuesAge[strColName] = rowAge
				} else if strColType == columnTypeFloat {
					var calcVal float64

					// Get old value
					oldVal, _ := bt.oldValues[strColName].(float64)
					if fColValue > oldVal {
						// Calculate the delta
						calcVal = (fColValue - oldVal) / float64(delta.Seconds())
					} else {
						calcVal = 0
					}

					// Add the delta value to the event
					event[strEventColName] = calcVal

					// Save current values as old values
					bt.oldValues[strColName] = fColValue
					bt.oldValuesAge[strColName] = rowAge
				} else {
					event[strEventColName] = strColValue
				}
			}
		}
	} else { // Not a delta column, add the value to the event as is
		if strColType == columnTypeString {
			event[strEventColName] = strColValue
		} else if strColType == columnTypeInt {
			event[strEventColName] = nColValue
		} else if strColType == columnTypeFloat {
			event[strEventColName] = fColValue
		}
	}

	// Great success!
	return nil
}

// generateEventFromRow creates a new event from the row data and returns it
func (bt *Mysqlbeat) generateEventFromRow(row *sql.Rows, columns []string, queryType string, rowAge time.Time) (common.MapStr, error) {

	// Make a slice for the values
	values := make([]sql.RawBytes, len(columns))

	// Copy the references into such a []interface{} for row.Scan
	scanArgs := make([]interface{}, len(values))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	// Create the event and populate it
	event := common.MapStr{
		"@timestamp": common.Time(rowAge),
		"type":       queryType,
	}

	// Get RawBytes from data
	err := row.Scan(scanArgs...)
	if err != nil {
		return nil, err
	}

	// Loop on all columns
	for i, col := range values {
		// Get column name and string value
		strColName := string(columns[i])
		strColValue := string(col)
		strColType := columnTypeString

		// Skip column proccessing when query type is show-slave-delay and the column isn't Seconds_Behind_Master
		if queryType == queryTypeSlaveDelay && strColName != columnNameSlaveDelay {
			continue
		}

		// Set the event column name to the original column name (as default)
		strEventColName := strColName

		// Remove unneeded suffix, add _PERSECOND to calculated columns
		if strings.HasSuffix(strColName, bt.deltaKeyWildcard) {
			strEventColName = strings.Replace(strColName, bt.deltaKeyWildcard, "", 1)
		} else if strings.HasSuffix(strColName, bt.deltaWildcard) {
			strEventColName = strings.Replace(strColName, bt.deltaWildcard, "_PERSECOND", 1)
		}

		// Try to parse the value to an int64
		nColValue, err := strconv.ParseInt(strColValue, 0, 64)
		if err == nil {
			strColType = columnTypeInt
		}

		// Try to parse the value to a float64
		fColValue, err := strconv.ParseFloat(strColValue, 64)
		if err == nil {
			// If it's not already an established int64, set type to float
			if strColType == columnTypeString {
				strColType = columnTypeFloat
			}
		}

		// If the column name ends with the deltaWildcard
		if (queryType == queryTypeSingleRow || queryType == queryTypeMultipleRows) && strings.HasSuffix(strColName, bt.deltaWildcard) {

			var strKey string

			// Get unique row key, if it's a single row - use the column name
			if queryType == queryTypeSingleRow {
				strKey = strColName
			} else if queryType == queryTypeMultipleRows {

				// If the query has multiple rows, a unique row key must be defind using the delta key wildcard and the column name
				strKey, err = getKeyFromRow(bt, values, columns)
				if err != nil {
					return nil, err
				}

				strKey += strColName
			}

			var exists bool
			_, exists = bt.oldValues[strKey]

			// If an older value doesn't exist
			if !exists {
				// Save the current value in the oldValues array
				bt.oldValuesAge[strKey] = rowAge

				if strColType == columnTypeString {
					bt.oldValues[strKey] = strColValue
				} else if strColType == columnTypeInt {
					bt.oldValues[strKey] = nColValue
				} else if strColType == columnTypeFloat {
					bt.oldValues[strKey] = fColValue
				}
			} else {
				// If found the old value's age
				if dtOldAge, ok := bt.oldValuesAge[strKey].(time.Time); ok {
					delta := rowAge.Sub(dtOldAge)

					if strColType == columnTypeInt {
						var calcVal int64

						// Get old value
						oldVal, _ := bt.oldValues[strKey].(int64)

						if nColValue > oldVal {
							// Calculate the delta
							devResult := float64((nColValue - oldVal)) / float64(delta.Seconds())
							// Round the calculated result back to an int64
							calcVal = roundF2I(devResult, .5)
						} else {
							calcVal = 0
						}

						// Add the delta value to the event
						event[strEventColName] = calcVal

						// Save current values as old values
						bt.oldValues[strKey] = nColValue
						bt.oldValuesAge[strKey] = rowAge
					} else if strColType == columnTypeFloat {
						var calcVal float64
						oldVal, _ := bt.oldValues[strKey].(float64)

						if fColValue > oldVal {
							// Calculate the delta
							calcVal = (fColValue - oldVal) / float64(delta.Seconds())
						} else {
							calcVal = 0
						}

						// Add the delta value to the event
						event[strEventColName] = calcVal

						// Save current values as old values
						bt.oldValues[strKey] = fColValue
						bt.oldValuesAge[strKey] = rowAge
					} else {
						event[strEventColName] = strColValue
					}
				}
			}
		} else { // Not a delta column, add the value to the event as is
			if strColType == columnTypeString {
				event[strEventColName] = strColValue
			} else if strColType == columnTypeInt {
				event[strEventColName] = nColValue
			} else if strColType == columnTypeFloat {
				event[strEventColName] = fColValue
			}
		}
	}

	// If the event has no data, set to nil
	if len(event) == 2 {
		event = nil
	}

	return event, nil
}

// getKeyFromRow is a function that returns a unique key from row
func getKeyFromRow(bt *Mysqlbeat, values []sql.RawBytes, columns []string) (strKey string, err error) {

	keyFound := false

	// Loop on all columns
	for i, col := range values {
		// Get column name and string value
		if strings.HasSuffix(string(columns[i]), bt.deltaKeyWildcard) {
			strKey += string(col)
			keyFound = true
		}
	}

	if !keyFound {
		err = fmt.Errorf("query type multiple-rows requires at least one delta key column")
	}

	return strKey, err
}

// roundF2I is a function that returns a rounded int64 from a float64
func roundF2I(val float64, roundOn float64) (newVal int64) {
	var round float64

	digit := val
	_, div := math.Modf(digit)
	if div >= roundOn {
		round = math.Ceil(digit)
	} else {
		round = math.Floor(digit)
	}

	return int64(round)
}

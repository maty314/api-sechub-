# Technical Specifications - SecHub API Service

## Overview

The SecHub API Service is a Flask-based microservice that acts as a bridge between Kubernetes Trivy Operator scan reports and DefectDojo (SecHub) security management platform. It receives scan reports from Kubernetes operators and automatically imports them into DefectDojo engagements for security analysis and tracking.

## Architecture

- **Framework**: Flask (Python)
- **Port**: 8080
- **Host**: 0.0.0.0 (all interfaces)
- **Debug Mode**: Enabled
- **External Dependencies**: DefectDojo API, Kubernetes Trivy Operator

## Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `sechubURL` | Base URL of the DefectDojo instance | Yes | `https://defectdojo.company.com` |
| `sechubToken` | API authentication token for DefectDojo | Yes | `abc123def456...` |
| `product` | DefectDojo product ID for engagement creation | Yes | `123` |
| `productName` | Human-readable product name for reports | Yes | `My Application` |

## API Endpoints

### 1. Health Check Endpoint

**Endpoint**: `GET /`
**Purpose**: Health check and service availability
**Response**: Empty response with HTTP 200 status
**Usage**: Kubernetes liveness/readiness probes

### 2. Report Processing Endpoint

**Endpoint**: `POST /report`
**Purpose**: Process Trivy Operator scan reports and import to DefectDojo
**Content-Type**: `application/json`

#### Request Payload Structure
```json
{
  "verb": "string",
  "operatorObject": {
    "kind": "string",
    "metadata": {
      "name": "string",
      "namespace": "string"
    },
    "managedFields": [
      {
        "operation": "string"
      }
    ],
    "spec": {},
    "status": {}
  }
}
```

#### Response Structure
```json
{
  "status": "success|error",
  "reportVerb": "string",
  "reportData": {},
  "reportKind": "string",
  "reportName": "string",
  "reportNamespace": "string",
  "reportOperation": "string"
}
```

## Core Functions

### 1. `get_sechub_engagements()`

**Purpose**: Retrieves all engagements for a specific product from DefectDojo

**Parameters**: None (uses environment variables)

**Returns**: 
- `list`: List of engagement objects if successful
- `None`: If API call fails

**Behavior**:
- Makes GET request to `/api/v2/engagements/?product={product_id}`
- Uses Bearer token authentication
- Extracts `results` array from response
- Handles HTTP errors gracefully

**Error Handling**: Returns `None` for any non-200 status code

### 2. `get_engagement_by_name(engagement_name)`

**Purpose**: Finds a specific engagement by name within the product

**Parameters**:
- `engagement_name` (str): Name of the engagement to find

**Returns**:
- `dict`: Engagement object if found
- `None`: If engagement not found or API error

**Behavior**:
- Calls `get_sechub_engagements()` to get all engagements
- Iterates through engagements to find matching name
- Returns first match found

**Dependencies**: `get_sechub_engagements()`

### 3. `get_tests_by_engagement_id(engagement_id)`

**Purpose**: Retrieves all tests associated with a specific engagement

**Parameters**:
- `engagement_id` (int/str): ID of the engagement

**Returns**:
- `list`: List of test objects if successful
- `None`: If API call fails

**Behavior**:
- Makes GET request to `/api/v2/tests/?engagement={engagement_id}`
- Uses Bearer token authentication
- Extracts `results` array from response

**Error Handling**: Returns `None` for any non-200 status code

### 4. `engagement_has_tests(engagement_id)`

**Purpose**: Checks if an engagement has any associated tests

**Parameters**:
- `engagement_id` (int/str): ID of the engagement to check

**Returns**:
- `bool`: `True` if engagement has tests, `False` otherwise
- `False`: If API call fails (treated as no tests)

**Behavior**:
- Calls `get_tests_by_engagement_id()`
- Returns boolean based on whether tests list is non-empty
- Handles API failures by returning `False`

**Dependencies**: `get_tests_by_engagement_id()`

### 5. `create_sechub_engagement(engagement_name, product_id)`

**Purpose**: Creates a new engagement in DefectDojo

**Parameters**:
- `engagement_name` (str): Name for the new engagement
- `product_id` (int/str): ID of the product to associate with

**Returns**:
- `int`: HTTP status code of the creation request

**Behavior**:
- Calculates start date as today
- Calculates end date as 365 days from today
- Makes POST request to `/api/v2/engagements/`
- Sends engagement data as form data
- Logs response for debugging

**Data Structure**:
```json
{
  "name": "engagement_name",
  "product": "product_id",
  "target_start": "YYYY-MM-DD",
  "target_end": "YYYY-MM-DD"
}
```

**Error Handling**: Returns HTTP status code (may be error code)

### 6. `import_findings_to_engagement(report_data, engagement_name, product_name, report_name, import_type='import-scan')`

**Purpose**: Imports scan findings into a DefectDojo engagement

**Parameters**:
- `report_data` (file-like object): JSON data of the scan report
- `engagement_name` (str): Name of the target engagement
- `product_name` (str): Name of the product
- `report_name` (str): Name of the report
- `import_type` (str): Type of import ('import-scan' or 'reimport-scan')

**Returns**:
- `tuple`: (status_code, error_message)
  - `(200|201, None)`: Success
  - `(error_code, error_text)`: API error
  - `(None, exception_message)`: Request exception

**Behavior**:
- Processes service name by removing hash suffixes from report name
- Sets up multipart form data with file upload
- Configures import parameters for Trivy Operator scans
- Makes POST request to `/api/v2/{import_type}/`
- Handles both successful imports and various error conditions

**Import Parameters**:
```json
{
  "minimum_severity": "Critical",
  "active": true,
  "verified": true,
  "scan_type": "Trivy Operator Scan",
  "close_old_findings": true,
  "push_to_jira": false,
  "deduplication_on_engagement": true,
  "group_by": "component_name",
  "product_name": "product_name",
  "scan_date": "YYYY-MM-DD",
  "engagement_name": "engagement_name",
  "service": "processed_service_name"
}
```

**Error Handling**: 
- Catches `requests.RequestException`
- Returns detailed error messages including response details
- Logs errors for debugging

## Workflow

### 1. Report Reception
1. Service receives POST request at `/report` endpoint
2. Extracts JSON payload containing `verb` and `operatorObject`
3. Parses operator object metadata (kind, name, namespace, operation)

### 2. Engagement Management
1. Uses `reportKind` as engagement name
2. Calls `get_engagement_by_name()` to check if engagement exists
3. If engagement doesn't exist:
   - Calls `create_sechub_engagement()` to create new engagement
   - Waits 1 second for creation to complete
   - Re-checks for engagement existence
   - Returns error if creation fails

### 3. Import Strategy Decision
1. Gets engagement ID from found/created engagement
2. Calls `engagement_has_tests()` to check existing tests
3. Determines import type:
   - `import-scan`: If no existing tests (first import)
   - `reimport-scan`: If tests already exist (update)

### 4. Report Processing
1. Converts operator object to JSON string
2. Creates file-like object from JSON data
3. Processes service name by removing hash suffixes
4. Calls `import_findings_to_engagement()` with appropriate parameters

### 5. Response Generation
1. Logs import success/failure
2. Returns JSON response with:
   - Status and all extracted report metadata
   - Original report data
   - Processing results

## Data Flow

```
Kubernetes Trivy Operator
         ↓
    POST /report
         ↓
   Extract Metadata
         ↓
   Check/Create Engagement
         ↓
   Determine Import Type
         ↓
   Process Report Data
         ↓
   Import to DefectDojo
         ↓
   Return Response
```

## Error Handling

### API Communication Errors
- Network timeouts and connection failures
- HTTP error responses from DefectDojo
- Authentication failures
- Malformed responses

### Business Logic Errors
- Engagement creation failures
- Import processing errors
- Missing required data
- Invalid engagement names

### Logging and Debugging
- All API requests logged with status codes and responses
- Debug mode enabled for detailed error information
- Error messages include full context and response details

## Security Considerations

- API token authentication for all DefectDojo communications
- No sensitive data logged in production
- Input validation on incoming JSON payloads
- Secure handling of file uploads

## Performance Characteristics

- Single-threaded Flask application
- Synchronous API calls to DefectDojo
- 1-second delay after engagement creation
- No caching implemented
- Memory usage scales with report size

## Dependencies

- **Flask**: Web framework
- **requests**: HTTP client for API calls
- **json**: JSON processing
- **io**: File-like object handling
- **re**: Regular expressions for string processing
- **datetime**: Date/time calculations
- **time**: Sleep functionality

## Deployment Considerations

- Runs on port 8080
- Binds to all interfaces (0.0.0.0)
- Debug mode enabled (should be disabled in production)
- Requires network access to DefectDojo instance
- Environment variables must be properly configured
- Suitable for Kubernetes deployment with proper health checks

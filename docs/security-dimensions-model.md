# Security Dimensions Model (Bell-LaPadula Based)

**Date**: March 9, 2026
**Purpose**: Define standardized security dimensions for data classification and access control

---

## Bell-LaPadula Model Mapping

### Classic Bell-LaPadula
```
Clearance = (SecurityLevel, {Compartments})
Example: (Secret, {NATO, NUCLEAR})

Access Rules:
- Read: User.level >= Object.level (read down)
- Write: User.level <= Object.level (write up, prevents leakage)
- Compartments: User.compartments ⊇ Object.compartments (need-to-know)
```

### Our Data Security Model
```
Classification = (
    SensitivityLevel,      // Hierarchical (like Security Level)
    {RegulatoryScopes},    // Compartments (PII, PHI, etc.)
    {GeographicScopes},    // Compartments (APAC, EU, etc.)
    {FunctionalPurposes},  // Compartments (Analytics, etc.)
    DataType               // Informational (helps routing)
)
```

---

## Security Dimensions

### Dimension 1: **Sensitivity Level** (Hierarchical Lattice)

**Property**: Strictly ordered vertical hierarchy

**Levels**:
```
0. Public       → Anyone can read
1. Internal     → Company employees only
2. Confidential → Need-to-know basis
3. Restricted   → Executive/legal approval required
4. Secret       → Highest classification
```

**Access Rule (Read)**:
```
user.sensitivity_level >= data.sensitivity_level
```

**Example**:
- User with "Confidential" clearance can read: Public, Internal, Confidential
- User with "Confidential" clearance CANNOT read: Restricted, Secret

**Column Metadata**:
```
"security.sensitivity": "confidential"
```

---

### Dimension 2: **Regulatory/Compliance Scope** (Compartments)

**Property**: Non-hierarchical, multiple can apply simultaneously

**Compartments**:
```
- PII         → Personally Identifiable Information (GDPR, CCPA)
- PHI         → Protected Health Information (HIPAA)
- PCI         → Payment Card Industry data (PCI-DSS)
- Financial   → Financial data (SOX, GLBA)
- GDPR        → EU General Data Protection Regulation
- ExportCtrl  → Export controlled data (ITAR, EAR)
- LegalPriv   → Attorney-client privileged
- TradeSecret → Trade secret / IP
```

**Access Rule (Read)**:
```
user.regulatory_scopes ⊇ data.regulatory_scopes
(User must have ALL required regulatory clearances)
```

**Example**:
- Data marked: {PII, Financial}
- User needs: {PII} AND {Financial} clearances
- User with {PII} only → DENIED
- User with {PII, Financial, PHI} → ALLOWED

**Column Metadata**:
```
"security.regulatory": "pii,financial"
```

---

### Dimension 3: **Geographic Scope** (Jurisdictional Compartments)

**Property**: Can be hierarchical (Country → Region → Global) OR flat

**Scopes**:
```
Regions:
- APAC        → Asia-Pacific
- EMEA        → Europe, Middle East, Africa
- AMER        → Americas (North + South)
- GLOBAL      → Worldwide

Countries:
- US          → United States
- EU          → European Union
- CN          → China
- IN          → India
- UK          → United Kingdom
- CA          → Canada
```

**Access Rule (Read)**:
```
user.geographic_scopes ∩ data.geographic_scopes ≠ ∅
(User needs AT LEAST ONE matching region)
```

**Example**:
- Data marked: {APAC, EMEA}
- User with {APAC} → ALLOWED (has APAC access)
- User with {AMER} → DENIED (no overlap)
- User with {GLOBAL} → ALLOWED (global includes all)

**Hierarchy**:
```
GLOBAL
  ├── APAC
  │     ├── IN (India)
  │     ├── CN (China)
  │     └── ...
  ├── EMEA
  │     ├── EU
  │     ├── UK
  │     └── ...
  └── AMER
        ├── US
        ├── CA
        └── ...
```

**Column Metadata**:
```
"security.geographic": "apac,emea"
```

**Special Case - Data Residency**:
- Row value determines region: `region="APAC"` → sets APAC bit
- Column metadata just marks: "this column contains geographic scope"

---

### Dimension 4: **Functional Purpose** (Purpose Limitation)

**Property**: Non-hierarchical, based on consent/legitimate use (GDPR Article 5)

**Purposes**:
```
- Analytics     → Business analytics, BI dashboards
- Operations    → Day-to-day business operations
- Marketing     → Marketing campaigns, promotions
- Research      → R&D, academic research
- Training      → ML model training
- Audit         → Compliance audits, investigations
- Support       → Customer support operations
- Development   → Software development/testing
```

**Access Rule (Read)**:
```
user.purposes ∩ data.purposes ≠ ∅
(User needs AT LEAST ONE allowed purpose)
```

**Example**:
- Data marked: {Analytics, Operations}
- User with purpose {Analytics} → ALLOWED
- User with purpose {Marketing} → DENIED
- User with purpose {Analytics, Marketing} → ALLOWED (has Analytics)

**Column Metadata**:
```
"security.purpose": "analytics,operations"
```

---

### Dimension 5: **Data Type/Category** (Informational)

**Property**: Descriptive, helps determine other dimensions

**Types**:
```
- CustomerData   → Customer records
- EmployeeData   → HR/employee information
- FinancialData  → Financial records, transactions
- HealthData     → Medical/health records
- SystemLogs     → System logs, telemetry
- TransactionData → Business transactions
```

**Access Rule**: No direct access control, but:
- Helps auto-classify (HealthData → likely PHI)
- Routing/auditing purposes
- Data catalog integration

**Column Metadata**:
```
"security.datatype": "customer_data"
```

---

## Bitmap Allocation (128 bits)

### _sec_lo (Bits 0-63)

#### Bits 0-3: Sensitivity Level (4 bits, hierarchical)
```
Bit 0: public       (0x1)
Bit 1: internal     (0x2)
Bit 2: confidential (0x4)
Bit 3: restricted   (0x8)
```

#### Bits 8-23: Regulatory Scope (16 bits, compartments)
```
Bit 8:  pii             (0x100)
Bit 9:  phi             (0x200)
Bit 10: pci             (0x400)
Bit 11: financial       (0x800)
Bit 12: gdpr            (0x1000)
Bit 13: export_control  (0x2000)
Bit 14: legal_privilege (0x4000)
Bit 15: trade_secret    (0x8000)
Bits 16-23: Reserved for more regulatory
```

#### Bits 24-39: Geographic Scope (16 bits, compartments)
```
Bit 24: region_apac   (0x1000000)
Bit 25: region_emea   (0x2000000)
Bit 26: region_amer   (0x4000000)
Bit 27: region_global (0x8000000)
Bit 28: country_us    (0x10000000)
Bit 29: country_eu    (0x20000000)
Bit 30: country_cn    (0x40000000)
Bit 31: country_in    (0x80000000)
Bits 32-39: More countries
```

#### Bits 40-55: Functional Purpose (16 bits, compartments)
```
Bit 40: purpose_analytics   (0x10000000000)
Bit 41: purpose_operations  (0x20000000000)
Bit 42: purpose_marketing   (0x40000000000)
Bit 43: purpose_research    (0x80000000000)
Bit 44: purpose_training    (0x100000000000)
Bit 45: purpose_audit       (0x200000000000)
Bit 46: purpose_support     (0x400000000000)
Bit 47: purpose_development (0x800000000000)
Bits 48-55: More purposes
```

#### Bits 56-63: Data Type (8 bits, informational)
```
Bit 56: datatype_customer    (0x100000000000000)
Bit 57: datatype_employee    (0x200000000000000)
Bit 58: datatype_financial   (0x400000000000000)
Bit 59: datatype_health      (0x800000000000000)
Bit 60: datatype_system_logs (0x1000000000000000)
Bits 61-63: Schema version (3 bits, 0-7)
```

### _sec_hi (Bits 64-127)
Reserved for future dimensions and extended compartments.

---

## Column Metadata Standard

### Format
```
Key-value pairs stored in Parquet column metadata:

"security.sensitivity": "<level>"
"security.regulatory": "<scope1>,<scope2>,..."
"security.geographic": "<region_or_country>"
"security.purpose": "<purpose1>,<purpose2>,..."
"security.datatype": "<type>"
"security.derivation": "<auto|manual|ml>"
```

### Example 1: Email Column
```python
{
  "security.sensitivity": "internal",
  "security.regulatory": "pii,gdpr",
  "security.datatype": "customer_data",
  "security.derivation": "auto"
}
```

### Example 2: Salary Column
```python
{
  "security.sensitivity": "confidential",
  "security.regulatory": "pii,financial",
  "security.datatype": "employee_data",
  "security.derivation": "auto"
}
```

### Example 3: Region Column (Special - Value-Based)
```python
{
  "security.geographic": "value_based",  # Read from column value
  "security.datatype": "customer_data",
  "security.derivation": "auto"
}
```

**Interpretation**: Column contains region values like "APAC", "EMEA". Characterization pipeline reads the VALUE and sets appropriate geographic bits.

---

## Access Control Matrix

### User Permission Example
```json
{
  "user_id": "analyst@co.com",
  "sensitivity_level": "confidential",
  "regulatory_scopes": ["pii", "financial"],
  "geographic_scopes": ["apac", "emea"],
  "purposes": ["analytics", "operations"]
}
```

### OPA Policy (Rego) Example
```rego
# Compute permitted bitmap
permitted_lo := bits_to_mask(permitted_dimensions)

permitted_dimensions := sensitivity_bits | regulatory_bits | geo_bits | purpose_bits

# Sensitivity (hierarchical - user can read down)
sensitivity_bits := {bit |
    user_level := sensitivity_levels[input.user.sensitivity_level]
    data_level := sensitivity_levels[_]
    data_level <= user_level
    bit := sensitivity_bits[_]
}

# Regulatory (compartments - user must have all)
regulatory_bits := {bit |
    scope := input.user.regulatory_scopes[_]
    bit := regulatory_bits[scope]
}

# Geographic (compartments - user needs at least one match)
geo_bits := {bit |
    region := input.user.geographic_scopes[_]
    bit := geo_bits[region]
}

# Purpose (compartments - user needs at least one match)
purpose_bits := {bit |
    purpose := input.user.purposes[_]
    bit := purpose_bits[purpose]
}
```

---

## Characterization Pipeline Workflow

### 1. Read Column Metadata
```python
import pyarrow.parquet as pq

schema = pq.read_schema(parquet_file)
for field in schema:
    metadata = field.metadata or {}
    if b'security.sensitivity' in metadata:
        sensitivity = metadata[b'security.sensitivity'].decode()
        # Derive bitmap...
```

### 2. Derive Row Bitmap
```python
def derive_row_bitmap(row, schema_metadata):
    bitmap = 0

    # For each column with security metadata
    for column, markers in schema_metadata.items():

        # Sensitivity (constant per column)
        if 'sensitivity' in markers:
            bitmap |= sensitivity_to_bits(markers['sensitivity'])

        # Regulatory (constant per column)
        if 'regulatory' in markers:
            for scope in markers['regulatory']:
                bitmap |= regulatory_to_bits(scope)

        # Geographic (VALUE-BASED!)
        if markers.get('geographic') == 'value_based':
            region_value = row[column]  # e.g., "APAC"
            bitmap |= region_to_bits(region_value)

        # Purpose (constant per column)
        if 'purpose' in markers:
            for purpose in markers['purpose']:
                bitmap |= purpose_to_bits(purpose)

    return bitmap
```

---

## Benefits of This Model

### 1. **Standards-Based**
- Aligns with Bell-LaPadula (proven security model)
- Regulatory compliance built-in (GDPR, HIPAA, etc.)
- Industry-standard dimensions

### 2. **Flexible**
- Hierarchical where needed (sensitivity)
- Compartmentalized where needed (regulatory, geo, purpose)
- Extensible (128 bits, plenty of room)

### 3. **Self-Documenting**
- Column metadata describes security properties
- Humans can read Parquet schema to understand classifications
- Automated tools can discover security requirements

### 4. **Efficient**
- Bitmap operations (fast)
- Single mask check per row
- No complex logic at read time

### 5. **Portable**
- Works across all engines (Spark, Trino, DuckDB)
- Standard Parquet format
- No proprietary extensions

---

## Example: End-to-End Flow

### 1. Data Owner Annotates Schema
```python
# When creating Parquet file
schema = pa.schema([
    pa.field('name', pa.string(), metadata={
        b'security.sensitivity': b'internal',
        b'security.datatype': b'customer_data'
    }),
    pa.field('email', pa.string(), metadata={
        b'security.sensitivity': b'internal',
        b'security.regulatory': b'pii,gdpr',
        b'security.datatype': b'customer_data'
    }),
    pa.field('salary', pa.int64(), metadata={
        b'security.sensitivity': b'confidential',
        b'security.regulatory': b'pii,financial',
        b'security.datatype': b'employee_data'
    }),
    pa.field('region', pa.string(), metadata={
        b'security.geographic': b'value_based',
        b'security.datatype': b'customer_data'
    })
])
```

### 2. Characterization Pipeline Reads Metadata
```python
# Reads schema metadata
# Sees: email → PII + GDPR
#       salary → Confidential + Financial
#       region → value-based geographic
```

### 3. For Each Row, Derive Bitmap
```python
row = {'name': 'Alice', 'email': 'alice@example.com',
       'salary': 120000, 'region': 'APAC'}

bitmap = 0
bitmap |= INTERNAL         # From 'name' and 'email' columns
bitmap |= CONFIDENTIAL     # From 'salary' column
bitmap |= PII              # From 'email' and 'salary'
bitmap |= GDPR             # From 'email'
bitmap |= FINANCIAL        # From 'salary'
bitmap |= REGION_APAC      # From region VALUE = "APAC"

row['_sec_lo'] = bitmap
```

### 4. Write Secured Parquet File
```python
# Now file has:
# - Original columns (name, email, salary, region)
# - Security columns (_sec_lo, _sec_hi)
# - Schema metadata (security markers on columns)
```

### 5. Reader Filters Rows
```python
# Spark/Trino just checks bitmap
if (row._sec_lo & forbidden_mask) == 0:
    return row  # User can see this
else:
    skip row    # User cannot see this
```

---

## Next Steps

1. **Update Registry**: Add all dimensions to `registry/characterization.py`
2. **Metadata Reader**: Parse column metadata in characterization pipeline
3. **Auto-Derivation**: Implement metadata-driven bitmap derivation
4. **OPA Policy Update**: Support new dimensions in policy evaluation
5. **Documentation**: Usage guide for data owners

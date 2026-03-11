# Parquet Reader/Writer Flow Diagrams

## Reader Flow: From File to Application

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Application Code                               │
│                                                                         │
│  val reader = ParquetReader.builder(readSupport, path).build()        │
│  while ((record = reader.read()) != null) { ... }                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ read()
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ParquetReader<T>                                │
│                                                                         │
│  - Manages file I/O                                                    │
│  - Iterates through row groups                                         │
│  - Delegates record conversion to ReadSupport                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ prepareForRead()
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          ReadSupport<T>                                 │
│                                                                         │
│  - init(): Initialize with file schema                                 │
│  - prepareForRead(): Create RecordMaterializer                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ returns
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      RecordMaterializer<T>                              │
│                                                                         │
│  - getRootConverter(): Returns converter tree                          │
│  - getCurrentRecord(): Returns materialized record                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ uses
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Converter Hierarchy                                │
│                                                                         │
│  GroupConverter                                                        │
│    ├── PrimitiveConverter (name: string)                              │
│    ├── PrimitiveConverter (age: int)                                  │
│    └── GroupConverter (address)                                       │
│          ├── PrimitiveConverter (street: string)                      │
│          └── PrimitiveConverter (city: string)                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ receives column data
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Parquet Column Readers                               │
│                                                                         │
│  - Decompress pages                                                    │
│  - Decode values (PLAIN, DELTA, RLE, etc.)                            │
│  - Apply dictionary encoding if used                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ reads from
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Parquet File Format                               │
│                                                                         │
│  Magic Number (4 bytes): PAR1                                          │
│  ┌───────────────────────────────────────┐                            │
│  │ Row Group 0                           │                            │
│  │   Column Chunk (name)                 │                            │
│  │     Page 0 (compressed)               │                            │
│  │     Page 1 (compressed)               │                            │
│  │   Column Chunk (age)                  │                            │
│  │     Page 0 (compressed)               │                            │
│  └───────────────────────────────────────┘                            │
│  ┌───────────────────────────────────────┐                            │
│  │ Row Group 1                           │                            │
│  │   ...                                 │                            │
│  └───────────────────────────────────────┘                            │
│  Footer Metadata                                                       │
│    - Schema                                                            │
│    - Row group metadata                                                │
│    - Column statistics                                                 │
│  Magic Number (4 bytes): PAR1                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Writer Flow: From Application to File

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Application Code                               │
│                                                                         │
│  val writer = new ParquetWriter(path, writeSupport, ...)              │
│  writer.write(record1)                                                 │
│  writer.write(record2)                                                 │
│  writer.close()                                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ write(record)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ParquetWriter<T>                                │
│                                                                         │
│  - Manages file I/O and buffering                                     │
│  - Tracks row group size                                               │
│  - Delegates record conversion to WriteSupport                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ write(record)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          WriteSupport<T>                                │
│                                                                         │
│  - init(): Return schema and metadata                                 │
│  - prepareForWrite(): Set up RecordConsumer                            │
│  - write(record): Convert T → Parquet format                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ calls methods on
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         RecordConsumer                                  │
│                                                                         │
│  Example call sequence for record:                                    │
│    startMessage()                                                      │
│      startField("name", 0)                                            │
│        addBinary("Alice")                                             │
│      endField("name", 0)                                              │
│      startField("age", 1)                                             │
│        addInteger(30)                                                 │
│      endField("age", 1)                                               │
│      startField("address", 2)                                         │
│        startGroup()                                                   │
│          startField("city", 0)                                        │
│            addBinary("Seattle")                                       │
│          endField("city", 0)                                          │
│        endGroup()                                                     │
│      endField("address", 2)                                           │
│    endMessage()                                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ buffers values
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Column Writers                                     │
│                                                                         │
│  - Buffer column values in memory                                     │
│  - When page size reached:                                             │
│      - Encode values (PLAIN, DELTA, RLE_DICTIONARY, etc.)             │
│      - Compress page (SNAPPY, GZIP, LZ4, ZSTD)                        │
│      - Write page to file                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ writes to
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Parquet File (being written)                         │
│                                                                         │
│  Magic Number: PAR1                                                    │
│  Row Group 0 (in progress)                                             │
│    name column chunk                                                   │
│      [page data compressed]                                            │
│    age column chunk                                                    │
│      [page data compressed]                                            │
│  (Footer written on close)                                             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Secured Reader Flow (Our Plugin)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Application Code                               │
│                                                                         │
│  // 1. Create security config                                         │
│  val provider = new OpaSecurityPolicyProvider(opaUrl, false)          │
│  val user = new UserContext(userId, roles, jurisdiction, attrs)       │
│  val config = new SecurityConfig(provider, user, false)               │
│                                                                         │
│  // 2. Create standard reader                                          │
│  val baseReader = ParquetReader.builder(readSupport, path).build()    │
│                                                                         │
│  // 3. Wrap with security                                              │
│  val reader = new SecuredParquetReader(baseReader, config, extractor) │
│                                                                         │
│  // 4. Read filtered records                                           │
│  while ((record = reader.read()) != null) { ... }                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ read()
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SecuredParquetReader<T>                            │
│                                                                         │
│  Constructor:                                                          │
│    1. Store delegate reader                                            │
│    2. Call OPA once: permittedMask = provider.getPermittedMask(user)  │
│       └─► OPA returns: PermittedMask{lo=0x10103, hi=0x0}             │
│                                                                         │
│  read():                                                               │
│    loop:                                                               │
│      record = delegate.read()  // Read from base reader               │
│      if record == null: return null  // EOF                           │
│      if !hasSecurityColumns(record): return record  // Unsecured      │
│                                                                         │
│      secLo = extractSecLo(record)  // Extract _sec_lo                 │
│      secHi = extractSecHi(record)  // Extract _sec_hi                 │
│                                                                         │
│      if permittedMask.isPermitted(secLo, secHi):                      │
│        return record  // ✓ Allowed                                    │
│      else:                                                             │
│        continue loop  // ✗ Filtered, read next                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ delegate.read()
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Standard ParquetReader<T>                          │
│                                                                         │
│  - Reads all records from file                                        │
│  - No knowledge of security filtering                                  │
│  - Returns records with all columns including _sec_lo/_sec_hi         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  Parquet File with Security Columns                     │
│                                                                         │
│  Row 1: {name: "Alice",  age: 30, _sec_lo: 0x10001, _sec_hi: 0}      │
│          internal (bit 0) + region_apac (bit 16)                      │
│          ✓ Permitted for APAC analyst                                 │
│                                                                         │
│  Row 2: {name: "Bob",    age: 35, _sec_lo: 0x10102, _sec_hi: 0}      │
│          confidential (bit 1) + pii (bit 8) + region_apac (bit 16)   │
│          ✓ Permitted for APAC analyst with PII access                │
│                                                                         │
│  Row 3: {name: "Charlie", age: 40, _sec_lo: 0x20208, _sec_hi: 0}     │
│          restricted (bit 3) + phi (bit 9) + region_emea (bit 17)     │
│          ✗ Filtered (EMEA region, not APAC)                           │
│                                                                         │
│  Row 4: {name: "Dave",   age: 28, _sec_lo: 0x20001, _sec_hi: 0}      │
│          internal (bit 0) + region_emea (bit 17)                      │
│          ✗ Filtered (EMEA region, not APAC)                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Bitmap Filtering Logic

### Permission Check

```
User Context:
  userId: "analyst@co.com"
  roles: ["analyst", "apac_reader"]
  jurisdiction: "IN"

                    ▼ OPA Policy Evaluation

OPA Returns:
  permitted_lo: 0x10103
    = 0001 0000 0001 0000 0011 (binary)
    = bit 0 (internal) + bit 1 (confidential) + bit 8 (pii) + bit 16 (region_apac)

  permitted_hi: 0x0

                    ▼ For Each Row

Row: _sec_lo = 0x10001
  = 0001 0000 0000 0000 0001
  = bit 0 (internal) + bit 16 (region_apac)

Check:
  forbidden_lo = (~permitted_lo) & 0x7FFF_FFFF_FFFF_FFFF
               = (~0x10103) & 0x7FFF_FFFF_FFFF_FFFF
               = 0x7FFF_FFFF_FFEF_FEFC

  (row._sec_lo & forbidden_lo) == 0?
  (0x10001 & 0x7FFF_FFFF_FFEF_FEFC) == 0?
  0x0 == 0?
  ✓ YES → Row is permitted

                    ▼

Row: _sec_lo = 0x20001
  = 0010 0000 0000 0000 0001
  = bit 0 (internal) + bit 17 (region_emea)

Check:
  (row._sec_lo & forbidden_lo) == 0?
  (0x20001 & 0x7FFF_FFFF_FFEF_FEFC) == 0?
  0x20000 == 0?  (bit 17 is set in forbidden mask!)
  ✗ NO → Row is filtered
```

---

## Comparison: Standard vs Secured Reading

### Standard Reading

```
Application
     │
     │ read()
     ▼
ParquetReader
     │
     │ read all rows
     ▼
Parquet File
     │
     │ returns
     ▼
Application
     │
     └─► Rows: [Alice, Bob, Charlie, Dave]  (all 4 rows)
```

### Secured Reading

```
Application
     │
     │ read()
     ▼
SecuredParquetReader
     │
     ├─► (constructor) Call OPA once → get permitted mask
     │
     │ read() - filters in application memory
     ▼
ParquetReader
     │
     │ read all rows
     ▼
Parquet File
     │
     │ returns
     ▼
SecuredParquetReader
     │
     ├─► Alice:   _sec_lo=0x10001 → ✓ permitted
     ├─► Bob:     _sec_lo=0x10102 → ✓ permitted
     ├─► Charlie: _sec_lo=0x20208 → ✗ filtered (EMEA)
     └─► Dave:    _sec_lo=0x20001 → ✗ filtered (EMEA)
     │
     │ returns only permitted rows
     ▼
Application
     │
     └─► Rows: [Alice, Bob]  (2 of 4 rows)
```

---

## Performance Characteristics

### OPA Calls

```
Query Execution:
  ┌─────────────────────────────────────────┐
  │ Driver/Coordinator                      │
  │                                         │
  │ 1. Create SecuredParquetReader          │
  │    └─► Call OPA once                    │  ◄─── ONE OPA CALL
  │        permittedMask = getPermittedMask()│
  │                                         │
  │ 2. Distribute file splits to executors │
  │    Each executor gets:                  │
  │      - File split metadata              │
  │      - Permitted mask (constant)        │  ◄─── NO OPA CALLS
  └─────────────────────────────────────────┘
              │
              │ distribute
              ▼
  ┌─────────────────────────────────────────┐
  │ Executor 1                              │
  │   Read split 1                          │
  │   Apply bitmap filter (in-memory)       │  ◄─── Just bitmap math
  │   (permitted_mask is constant)          │
  └─────────────────────────────────────────┘

  ┌─────────────────────────────────────────┐
  │ Executor 2                              │
  │   Read split 2                          │
  │   Apply bitmap filter (in-memory)       │  ◄─── Just bitmap math
  │   (permitted_mask is constant)          │
  └─────────────────────────────────────────┘

  ┌─────────────────────────────────────────┐
  │ Executor N                              │
  │   Read split N                          │
  │   Apply bitmap filter (in-memory)       │  ◄─── Just bitmap math
  │   (permitted_mask is constant)          │
  └─────────────────────────────────────────┘
```

### Filtering Cost

```
Per-Row Cost:
  1. Extract _sec_lo (int64 read)              ~1 ns
  2. Extract _sec_hi (int64 read)              ~1 ns
  3. Bitwise AND with forbidden_lo             ~1 ns
  4. Bitwise AND with forbidden_hi             ~1 ns
  5. Compare with zero                         ~1 ns
     ────────────────────────────────────────
     Total: ~5 nanoseconds per row

Compare to:
  - Parquet decompression: ~100-1000 ns/row
  - Column decoding: ~10-100 ns/row
  - Network I/O: ~1000-10000 ns/row

Security filtering overhead: < 1% of total read cost
```

---

## Summary

- **ParquetReader** uses `ReadSupport` plugin pattern
- **ParquetWriter** uses `WriteSupport` plugin pattern
- **RecordMaterializer** converts Parquet → Application type
- **RecordConsumer** converts Application type → Parquet
- **SecuredParquetReader** wraps standard reader + adds filtering
- **OPA called once** per query (not per row)
- **Filtering happens in memory** with simple bitmap operations
- **Overhead is minimal** (<1% of total read cost)

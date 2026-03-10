# SecuredParquetReader Refactoring Summary

**Date**: March 9, 2026
**Change**: Simplified SecuredParquetReader from config-driven to mask-driven design

---

## What Changed

### Before (Option A): Reader Handles Policy Evaluation

```java
// Reader took SecurityConfig (policy provider + user context)
SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
    baseReader,
    securityConfig,        // Contains OPA provider + user
    columnExtractor
);
// ❌ Reader called OPA in constructor
// ❌ Mixed policy evaluation with filtering logic
```

### After (Option B): Reader is Pure Filter

```java
// Caller gets mask from OPA first
PermittedMask mask = policyProvider.getPermittedMask(userContext);

// Reader just filters with the mask
SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
    baseReader,
    mask,                  // Just the bitmap mask
    columnExtractor
);
// ✅ Reader is pure filtering logic
// ✅ No OPA calls, no policy dependencies
// ✅ Caller controls when/how OPA is called
```

---

## Why This is Better

### 1. **Simpler Design**
- Reader has one responsibility: filter rows based on bitmap
- No policy evaluation logic mixed in
- No dependency on `SecurityPolicyProvider` or `UserContext`

### 2. **More Flexible**
- Caller controls when OPA is called
- Caller can cache masks across multiple readers
- Caller can implement retry logic for OPA failures
- Easier to test (just pass different masks)

### 3. **Matches Real-World Usage**
Spark integration was already doing this:
```scala
// Spark calls OPA once
val permittedMask = policyProvider.getPermittedMask(userContext)

// Then filters inline (doesn't use SecuredParquetReader)
baseIterator.filter { row =>
  val secLo = row.getLong(secLoIdx)
  val secHi = row.getLong(secHiIdx)
  ((secLo & forbiddenLo) == 0) && ((secHi & forbiddenHi) == 0)
}
```

Now SecuredParquetReader matches this pattern.

### 4. **Better Separation of Concerns**
- **Policy Layer**: `SecurityPolicyProvider` → calls OPA, handles errors, caching
- **Filtering Layer**: `SecuredParquetReader` → applies bitmap math
- **Integration Layer**: Spark/Trino → orchestrates both

### 5. **Performance Benefits**
Caller can optimize OPA calls:
```java
// Call OPA once, use mask for multiple files
PermittedMask mask = policyProvider.getPermittedMask(user);

for (Path file : files) {
    ParquetReader base = ParquetReader.builder(...).build();
    SecuredParquetReader secured = new SecuredParquetReader(base, mask, extractor);
    // ... read file
}
// Only called OPA once, not N times!
```

---

## Files Changed

### 1. SecuredParquetReader.java

**Constructor signature changed:**
```java
// Before
public SecuredParquetReader(
    ParquetReader<T> delegate,
    SecurityConfig securityConfig,  // ❌ Removed
    SecurityColumnExtractor<T> columnExtractor
)

// After
public SecuredParquetReader(
    ParquetReader<T> delegate,
    PermittedMask permittedMask,    // ✅ Just the mask
    SecurityColumnExtractor<T> columnExtractor
)
```

**No longer calls OPA:**
```java
// Before (in constructor)
this.permittedMask = securityConfig.getPolicyProvider()
    .getPermittedMask(securityConfig.getUserContext());

// After (caller already has mask)
this.permittedMask = permittedMask;
```

### 2. IntegrationTest.java

**Updated all tests to call OPA first:**
```java
// Before
SecurityConfig config = new SecurityConfig(policyProvider, user, false);
SecuredParquetReader reader = new SecuredParquetReader(baseReader, config, extractor);

// After
PermittedMask permittedMask = policyProvider.getPermittedMask(user);
SecuredParquetReader reader = new SecuredParquetReader(baseReader, permittedMask, extractor);
```

### 3. README.md

Updated usage example to show caller calling OPA:
```java
// 2. Call OPA once to get permitted mask
PermittedMask permittedMask = provider.getPermittedMask(context);

// 3. Wrap with secured reader (just filtering, no OPA call)
SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
    baseReader,
    permittedMask,
    new GroupSecurityColumnExtractor()
);
```

---

## Impact Assessment

### ✅ What Still Works

- All existing tests pass (50 tests, 43 passing, 7 skipped)
- Spark integration compiles and works
- Core filtering logic unchanged
- Performance characteristics unchanged

### ⚠️ Breaking Change

This is a **breaking change** for any code using `SecuredParquetReader` directly:

**Migration Guide:**
```java
// Old code
SecurityConfig config = new SecurityConfig(provider, user, false);
SecuredParquetReader reader = new SecuredParquetReader(baseReader, config, extractor);

// New code (add one line)
PermittedMask mask = provider.getPermittedMask(user);  // ← Add this
SecuredParquetReader reader = new SecuredParquetReader(baseReader, mask, extractor);
```

### 📦 SecurityConfig.java Status

`SecurityConfig` is now **only used by higher-level code** (if at all):
- Not used by `SecuredParquetReader` anymore
- Could be used by Spark/Trino to bundle config together
- Could potentially be removed if engines don't use it

---

## Test Results

### Before Refactoring
```
Tests run: 50, Failures: 0, Errors: 0, Skipped: 7
```

### After Refactoring
```
Tests run: 50, Failures: 0, Errors: 0, Skipped: 7
✅ All tests pass!
```

### Build Status
```
[INFO] parquet-security-core: BUILD SUCCESS
[INFO] parquet-security-spark: BUILD SUCCESS
```

---

## Design Principles Validated

This refactoring reinforces our core architectural principles:

### ✅ Single Responsibility
- `SecuredParquetReader`: Pure filtering
- `SecurityPolicyProvider`: Policy evaluation
- Clear boundaries

### ✅ Dependency Inversion
- Reader depends on `PermittedMask` (data structure)
- Doesn't depend on `SecurityPolicyProvider` (behavior)
- More testable, more flexible

### ✅ Open/Closed
- Open for extension: Caller can implement custom caching, retry, etc.
- Closed for modification: Reader's filtering logic unchanged

### ✅ Simplicity
- Fewer concepts: No `SecurityConfig` in reader
- Clearer intent: "Here's the mask, filter with it"
- Easier to understand and debug

---

## Future Considerations

### 1. SecurityConfig Utility
If multiple engines need to bundle config, keep `SecurityConfig` as a convenience:
```java
// Optional utility for bundling
public class SecurityConfig {
    public static PermittedMask fetchMask(
        SecurityPolicyProvider provider,
        UserContext user
    ) {
        return provider.getPermittedMask(user);
    }
}
```

### 2. Caching Layer
Caller can now easily add caching:
```java
// Cache masks for 5 minutes
Cache<UserContext, PermittedMask> maskCache = CacheBuilder.newBuilder()
    .expireAfterWrite(5, TimeUnit.MINUTES)
    .build();

PermittedMask mask = maskCache.get(user, () ->
    policyProvider.getPermittedMask(user)
);
```

### 3. Batch Processing
Caller can optimize for batch scenarios:
```java
// Process 1000 files with one OPA call
PermittedMask mask = policyProvider.getPermittedMask(user);

files.parallelStream().forEach(file -> {
    ParquetReader base = openFile(file);
    SecuredParquetReader secured = new SecuredParquetReader(base, mask, extractor);
    processFile(secured);
});
```

---

## Conclusion

This refactoring:
- ✅ Simplifies `SecuredParquetReader` (pure filtering logic)
- ✅ Increases flexibility (caller controls OPA interaction)
- ✅ Matches real-world usage patterns (Spark already did this)
- ✅ Maintains all existing functionality
- ✅ All tests pass

**The reader is now a simple, focused component that does one thing well: filter rows based on bitmaps.**

# Unified OSS Framework Tests

This directory contains comprehensive unit tests for the Unified OSS Framework.

## Test Structure

```
tests/
├── __init__.py              # Test package initialization
├── conftest.py              # Shared fixtures and configuration
├── test_alarm_manager.py   # Fault management - alarm tests
├── test_correlation.py      # Fault management - correlation tests
├── test_normalization.py   # Fault management - normalization tests
├── test_config_drift.py    # Configuration - drift detection tests
├── test_kpi_manager.py     # Performance - KPI management tests
├── test_auth.py            # Security - authentication tests
├── test_authorization.py   # Security - authorization tests
└── test_config_workflow.py # Configuration - workflow tests
```

## Running Tests

### Run All Tests
```bash
pytest
```

### Run with Verbose Output
```bash
pytest -v
```

### Run Specific Test File
```bash
pytest tests/test_alarm_manager.py
```

### Run Specific Test Class
```bash
pytest tests/test_alarm_manager.py::TestAlarmManager
```

### Run Specific Test Method
```bash
pytest tests/test_alarm_manager.py::TestAlarmManager::test_create_alarm
```

### Run with Coverage Report
```bash
pytest --cov=unified_oss --cov-report=html
```

### Run Only Unit Tests
```bash
pytest -m unit
```

### Run Only Integration Tests
```bash
pytest -m integration
```

### Run Tests in Parallel
```bash
pytest -n auto
```

## Test Categories

### Unit Tests
- Test individual classes and functions in isolation
- Use mocked dependencies
- Fast execution

### Integration Tests
- Test multiple components working together
- May use simulated external dependencies
- Longer execution time

### Performance Tests
- Benchmark critical operations
- Verify performance requirements

## Writing Tests

### Test Naming Convention
- Test files: `test_<module_name>.py`
- Test classes: `Test<Feature>`
- Test methods: `test_<scenario>`

### Example Test Structure
```python
class TestFeature:
    """Tests for Feature class."""
    
    @pytest.mark.asyncio
    async def test_feature_success(self, fixture):
        """Test successful feature operation."""
        # Arrange
        input_data = fixture
        
        # Act
        result = await feature.operation(input_data)
        
        # Assert
        assert result.success is True
```

### Using Fixtures
```python
@pytest.fixture
def sample_alarm():
    """Create a sample alarm for testing."""
    return Alarm(
        alarm_id="test-001",
        severity="major",
        # ...
    )

def test_with_fixture(sample_alarm):
    """Test using fixture."""
    assert sample_alarm.alarm_id == "test-001"
```

### Async Tests
```python
@pytest.mark.asyncio
async def test_async_operation():
    """Test async operation."""
    result = await async_function()
    assert result is not None
```

## Test Coverage Goals

- Overall coverage: > 80%
- Critical paths: > 90%
- Error handling: > 85%

## Continuous Integration

Tests are automatically run on:
- Every pull request
- Every merge to main branch
- Scheduled nightly builds

## Dependencies

Install test dependencies:
```bash
pip install -r requirements-test.txt
```

## Debugging Tests

### Run with Print Statements
```bash
pytest -s tests/test_file.py
```

### Drop into Debugger on Failure
```bash
pytest --pdb tests/test_file.py
```

### Show Local Variables on Failure
```bash
pytest -l tests/test_file.py
```

## Best Practices

1. **Isolation**: Each test should be independent
2. **Clarity**: Test names should describe what is being tested
3. **Simplicity**: One assertion per test when possible
4. **Maintainability**: Use fixtures for common setup
5. **Speed**: Keep tests fast by mocking external dependencies
6. **Coverage**: Aim for meaningful coverage, not just high numbers

## Test Doubles

### Mocks
Used for verifying interactions:
```python
mock = MagicMock()
mock.method.return_value = "result"
```

### Async Mocks
For async functions:
```python
async_mock = AsyncMock()
async_mock.method.return_value = "result"
```

### Patches
For replacing dependencies:
```python
with patch('module.function') as mock_func:
    mock_func.return_value = "mocked"
    # test code
```

## Troubleshooting

### Import Errors
Make sure the src directory is in your Python path:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

### Async Test Issues
Ensure pytest-asyncio is installed and configured:
```bash
pip install pytest-asyncio
```

### Fixture Not Found
Check that fixtures are defined in conftest.py or the test file itself.

## Contributing

When adding new features, please:
1. Write corresponding unit tests
2. Ensure all existing tests pass
3. Maintain or improve code coverage
4. Follow the existing test patterns

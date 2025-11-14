# Contributing to Digital DNA

Terima kasih sudah tertarik berkontribusi pada Digital DNA! Panduan ini menjelaskan bagaimana Anda dapat berkontribusi.

## Code of Conduct

Kami berkomitmen pada inclusive dan respectful community. Semua kontributor harus:
- Treat everyone dengan respect dan dignity
- Welcome diverse perspectives dan backgrounds
- Provide constructive feedback
- Report inappropriate behavior

## Getting Started

### Prerequisites
- Python 3.11+
- Git
- Basic understanding of behavioral biometrics / security concepts

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/KalloloCoder/digital-dna.git
cd digital-dna

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy

# Run tests to verify setup
pytest tests/ -v
```

## How to Contribute

### 1. Bug Reports

Found a bug? Submit a detailed bug report:

```
Title: Brief description of the bug

Description:
- Expected behavior
- Actual behavior
- Steps to reproduce

Environment:
- Python version
- OS
- Module(s) affected

Logs/Error messages:
[Include relevant error traces]
```

### 2. Feature Requests

Have an idea? Share it with us:

```
Title: Feature: [Brief description]

Motivation:
Why should this feature be implemented?
What problem does it solve?

Proposed solution:
How should it work?
Any API/behavior changes?

Alternative solutions:
Any other approaches to consider?
```

### 3. Code Contributions

#### Step 1: Create Feature Branch
```bash
git checkout -b feature/your-feature-name
# or for bug fixes:
git checkout -b fix/bug-description
```

#### Step 2: Make Changes
- Write clear, concise code
- Follow coding standards (see below)
- Add tests for new functionality
- Update documentation

#### Step 3: Commit with Clear Messages
```bash
git commit -m "Type: Brief description

More detailed explanation of changes if needed.
- Point 1
- Point 2

Fixes #123 (if fixing an issue)
"
```

Commit types:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/modifications
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

#### Step 4: Push & Create Pull Request
```bash
git push origin feature/your-feature-name
```

Then create Pull Request on GitHub with:
- Clear title
- Description of changes
- Link to related issues
- Screenshots/benchmarks if applicable

## Coding Standards

### Style Guide

We follow PEP 8 with some conventions:

```python
# Bad
x=1+2
def foo(a,b):
    return a+b

# Good
x = 1 + 2
def foo(a, b):
    return a + b
```

### Code Formatting

```bash
# Format code with black
black agent/ generator/ verification/ federated/ policy/

# Check code style with flake8
flake8 agent/ generator/ verification/ federated/ policy/

# Type checking with mypy
mypy agent/ generator/ verification/ federated/ policy/
```

### Docstring Format

```python
def function_name(arg1: str, arg2: int) -> bool:
    """
    Short description of what function does.
    
    Longer description if needed, explaining:
    - What it does
    - Why it exists
    - Key algorithm if relevant
    
    Args:
        arg1: Description of arg1
        arg2: Description of arg2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When invalid arguments provided
        
    Example:
        >>> result = function_name("test", 42)
        >>> print(result)
        True
    """
    pass
```

### Type Hints

Always use type hints:

```python
from typing import Dict, List, Optional, Tuple

def process_vectors(
    vectors: List[Dict[str, Any]],
    threshold: float = 0.5
) -> Tuple[bool, List[str]]:
    """Process vectors and return results."""
    pass
```

## Testing Requirements

### Unit Tests
- Write tests for all new functions/classes
- Aim for >80% code coverage
- Test both happy path and error cases

```python
import unittest
from module import YourClass

class TestYourClass(unittest.TestCase):
    def setUp(self):
        """Setup test fixtures"""
        self.obj = YourClass()
    
    def test_normal_case(self):
        """Test normal operation"""
        result = self.obj.method()
        self.assertEqual(result, expected)
    
    def test_error_case(self):
        """Test error handling"""
        with self.assertRaises(ValueError):
            self.obj.method_that_fails()
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_agent.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test
pytest tests/test_agent.py::TestBehavioralCapture::test_initialization -v
```

## Documentation

### Update Documentation When:
- Adding new features
- Changing existing API
- Fixing bugs that were documented incorrectly
- Improving explanation of concepts

### Documentation Locations:
- `README.md`: Overview, quickstart, setup
- `docs/architecture.md`: System design, data models
- `docs/roadmap.md`: Development roadmap
- `CONTRIBUTING.md`: This file
- Code docstrings: Function/class documentation

## Pull Request Process

### Before Submitting

1. **Update from main branch**
   ```bash
   git fetch origin
   git rebase origin/main
   ```

2. **Run all checks**
   ```bash
   # Format code
   black .
   
   # Check style
   flake8 .
   
   # Type checking
   mypy .
   
   # Run tests
   pytest tests/ -v
   
   # Check coverage
   pytest tests/ --cov=. --cov-report=term-missing
   ```

3. **Create descriptive commit**
   ```bash
   git commit -m "type: description" -m "detailed explanation"
   ```

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other: ___

## Related Issue
Fixes #123

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing Done
- [ ] Unit tests added/updated
- [ ] All tests passing
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Changes reviewed locally
- [ ] Commits are clear and descriptive
```

### PR Review Process

1. **Automated checks** must pass (tests, style, coverage)
2. **Manual review** by maintainers
3. **Feedback & improvements** - respond to comments
4. **Approval** - PR approved by reviewer
5. **Merge** - maintainer merges to main branch

## Development Workflow

### Example: Adding New Feature

```bash
# 1. Create feature branch
git checkout -b feature/new-threat-detection

# 2. Implement feature
# - Edit verification/local_verifier.py
# - Add new detection method
# - Update docstrings

# 3. Write tests
# - Edit tests/test_verification.py
# - Add test cases for new method

# 4. Format & check
black verification/ tests/
pytest tests/test_verification.py -v

# 5. Commit changes
git add -A
git commit -m "feat: add new threat detection method

Implement advanced threat detection using graph analysis
for insider threat identification.

- Add GraphAnalyzer class
- Implement community detection algorithm
- Add comprehensive tests

Closes #45"

# 6. Push & create PR
git push origin feature/new-threat-detection
# Then create PR on GitHub
```

## Specialized Contributions

### 1. Algorithm Contributions
- Describe algorithm clearly
- Include mathematical formulation
- Provide research papers/references
- Add benchmarks comparing with alternatives

### 2. Security Contributions
- Report security issues privately to security@digitaldna.io
- Include proof of concept if possible
- Suggest fixes if known
- Follow coordinated disclosure practices

### 3. Documentation Contributions
- Fix typos and grammar
- Clarify confusing sections
- Add examples and use cases
- Improve code comments

### 4. ML/AI Contributions
- Include training data description
- Document model architecture
- Provide evaluation metrics
- Add example predictions

## Recognition

Contributors will be recognized in:
- GitHub Contributors page
- CONTRIBUTORS.md file
- Release notes
- Project blog posts

## Communication Channels

- **Issues**: Report bugs, request features
- **Discussions**: Questions, ideas, discussions
- **Pull Requests**: Code contributions
- **Email**: muhammadagustriananda@gmail.com
- **Slack** (coming soon): Community chat

## Additional Resources

- [Architecture Documentation](docs/architecture.md)
- [Testing Guide](docs/testing.md) (coming soon)
- [Security Policy](SECURITY.md) (coming soon)
- [Roadmap](docs/roadmap.md)

## FAQ

### Q: I'm new to open source, where do I start?
A: Look for issues labeled `good-first-issue` or `help-wanted`. Start with documentation or small bug fixes.

### Q: How long does PR review take?
A: Usually 24-48 hours during business days. Critical issues may be faster.

### Q: Can I work on multiple features at once?
A: It's better to focus on one feature at a time. Create separate branches for different features.

### Q: What if my PR gets rejected?
A: It's normal! Feedback helps improve code quality. Address comments and push improvements.

### Q: How do I report security issues?
A: Email muhammadagustriananda@gmail.com with details. Don't post publicly.

---

## Summary

We follow these principles:
1. **Quality over Speed** - Well-tested, documented code is better than fast code
2. **Collaboration** - Work together, ask questions, share ideas
3. **Respect** - Treat everyone with respect regardless of experience
4. **Transparency** - Discuss decisions openly, document rationale
5. **Continuous Learning** - Share knowledge, help others grow

Thank you for contributing! 🙏

---

**Last Updated**: November 14, 2025
**Version**: 1.0



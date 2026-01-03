import string
import re
import sys


class PasswordStrengthChecker:
    """
    Comprehensive password strength analyzer with detailed feedback.
    """
    
    # Common weak passwords and patterns
    COMMON_PASSWORDS = {
        'password', 'password123', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', 'letmein', 'dragon', 'baseball', 'football', 'master',
        'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow', 'superman',
        'qazwsx', 'michael', 'football', 'batman', '123456789', 'trust'
    }
    
    def __init__(self, password: str):
        """Initialize with a password to check."""
        self.password = password
        self.score = 0
        self.feedback = []
        self.strength_level = ""
    
    def check_length(self) -> int:
        """Check password length and award points."""
        length = len(self.password)
        points = 0
        
        if length < 8:
            self.feedback.append("❌ Password is too short (minimum 8 characters)")
            return 0
        elif length < 12:
            points = 1
            self.feedback.append("✓ Password length is acceptable (8-11 characters)")
        elif length < 16:
            points = 2
            self.feedback.append("✓ Password length is good (12-15 characters)")
        else:
            points = 3
            self.feedback.append("✅ Password length is excellent (16+ characters)")
        
        return points
    
    def check_uppercase(self) -> int:
        """Check for uppercase letters."""
        has_upper = any(c in string.ascii_uppercase for c in self.password)
        if has_upper:
            uppercase_chars = [c for c in self.password if c in string.ascii_uppercase]
            self.feedback.append(f"✓ Contains uppercase letters: {', '.join(uppercase_chars)}")
            return 1
        else:
            self.feedback.append("❌ No uppercase letters found (add A-Z)")
            return 0
    
    def check_lowercase(self) -> int:
        """Check for lowercase letters."""
        has_lower = any(c in string.ascii_lowercase for c in self.password)
        if has_lower:
            self.feedback.append("✓ Contains lowercase letters")
            return 1
        else:
            self.feedback.append("❌ No lowercase letters found (add a-z)")
            return 0
    
    def check_digits(self) -> int:
        """Check for numbers."""
        has_digit = any(c in string.digits for c in self.password)
        if has_digit:
            digits_found = [c for c in self.password if c in string.digits]
            self.feedback.append(f"✓ Contains numbers: {', '.join(digits_found)}")
            return 1
        else:
            self.feedback.append("❌ No numbers found (add 0-9)")
            return 0
    
    def check_special_chars(self) -> int:
        """Check for special characters."""
        has_special = any(c in string.punctuation for c in self.password)
        if has_special:
            special_chars = [c for c in self.password if c in string.punctuation]
            self.feedback.append(f"✓ Contains special characters: {', '.join(special_chars)}")
            return 1
        else:
            self.feedback.append("❌ No special characters found (add !@#$%^&*)")
            return 0
    
    def check_character_variety(self) -> int:
        """Check for character diversity."""
        unique_chars = len(set(self.password))
        total_chars = len(self.password)
        variety_ratio = unique_chars / total_chars
        
        if variety_ratio >= 0.8:
            self.feedback.append(f"✅ Excellent character variety ({unique_chars} unique of {total_chars})")
            return 1
        elif variety_ratio >= 0.6:
            self.feedback.append(f"✓ Good character variety ({unique_chars} unique of {total_chars})")
            return 0
        else:
            self.feedback.append(f"⚠️ Low character variety ({unique_chars} unique of {total_chars})")
            return -1
    
    def check_sequential_patterns(self) -> int:
        """Check for sequential numbers/letters (e.g., 123, abc)."""
        # Check for sequential numbers
        if re.search(r'0+|1+|2+|3+|4+|5+|6+|7+|8+|9+', self.password):
            if re.search(r'\d{3,}', self.password):
                self.feedback.append("⚠️ Avoid repeating numbers (111, 222, etc.)")
                return -1
        
        # Check for sequential letters
        if re.search(r'a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+', self.password.lower()):
            if re.search(r'[a-z]{3,}', self.password.lower()):
                self.feedback.append("✓ Avoid repeating letters (aaa, bbb, etc.)")
                return 0
        
        return 0
    
    def check_common_passwords(self) -> int:
        """Check against common weak passwords."""
        if self.password.lower() in self.COMMON_PASSWORDS:
            self.feedback.append("❌ This is a very common password - AVOID!")
            return -3
        
        # Check for simple patterns
        if re.match(r'^[a-zA-Z]+\d+$', self.password):
            if len(self.password) < 10:
                self.feedback.append("⚠️ Avoid simple patterns like 'password123'")
                return -1
        
        return 0
    
    def check_keyboard_patterns(self) -> int:
        """Check for keyboard patterns like qwerty, asdfgh."""
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '12345', 'abcdef']
        for pattern in keyboard_patterns:
            if pattern in self.password.lower():
                self.feedback.append(f"❌ Contains keyboard pattern '{pattern}' - avoid this")
                return -2
        
        return 0
    
    def calculate_strength(self) -> str:
        """Calculate overall strength level."""
        if self.score <= 0:
            return "VERY WEAK ❌"
        elif self.score <= 2:
            return "WEAK ⚠️"
        elif self.score <= 4:
            return "FAIR 🔶"
        elif self.score <= 6:
            return "GOOD ✓"
        elif self.score <= 8:
            return "STRONG ✅"
        else:
            return "VERY STRONG 🔒"
    
    def check_password(self) -> dict:
        """Run all checks and return results."""
        self.score = 0
        self.feedback = []
        
        # Run all checks
        self.score += self.check_length()
        self.score += self.check_uppercase()
        self.score += self.check_lowercase()
        self.score += self.check_digits()
        self.score += self.check_special_chars()
        self.score += self.check_character_variety()
        self.score += self.check_sequential_patterns()
        self.score += self.check_common_passwords()
        self.score += self.check_keyboard_patterns()
        
        # Ensure score doesn't go below 0
        self.score = max(0, self.score)
        
        # Cap maximum score at 10
        self.score = min(10, self.score)
        
        self.strength_level = self.calculate_strength()
        
        return {
            'password': '*' * len(self.password),  # Don't expose password
            'length': len(self.password),
            'score': self.score,
            'strength': self.strength_level,
            'feedback': self.feedback
        }
    
    def print_report(self):
        """Print a formatted report."""
        results = self.check_password()
        
        print("\n" + "="*50)
        print("   PASSWORD STRENGTH CHECKER v2.0")
        print("="*50)
        
        print(f"\n📊 PASSWORD ANALYSIS")
        print(f"   Length: {results['length']} characters")
        print(f"   Hidden: {results['password']}\n")
        
        print(f"📋 DETAILED FEEDBACK:")
        for item in results['feedback']:
            print(f"   {item}")
        
        print(f"\n🎯 SCORE: {results['score']}/10")
        print(f"💪 STRENGTH: {results['strength']}")
        
        # Recommendations
        if self.score < 7:
            print(f"\n💡 RECOMMENDATIONS:")
            if len(self.password) < 12:
                print(f"   • Increase password length to at least 12 characters")
            if not any(c in string.ascii_uppercase for c in self.password):
                print(f"   • Add uppercase letters (A-Z)")
            if not any(c in string.ascii_lowercase for c in self.password):
                print(f"   • Add lowercase letters (a-z)")
            if not any(c in string.digits for c in self.password):
                print(f"   • Add numbers (0-9)")
            if not any(c in string.punctuation for c in self.password):
                print(f"   • Add special characters (!@#$%^&*)")
        elif self.score >= 8:
            print(f"\n✅ Great password! It meets all security criteria.")
        
        print("\n" + "="*50 + "\n")


def main():
    """Main function to handle password checking."""
    if len(sys.argv) > 1:
        # Password provided as command-line argument
        password = sys.argv[1]
        checker = PasswordStrengthChecker(password)
        checker.print_report()
    else:
        # Interactive mode
        print("\n" + "="*50)
        print("   PASSWORD STRENGTH CHECKER v2.0")
        print("="*50 + "\n")
        
        while True:
            password = input("Enter a password to check (or 'quit' to exit): ")
            
            if password.lower() == 'quit':
                print("Goodbye!\n")
                break
            
            if len(password) == 0:
                print("⚠️ Please enter a password.\n")
                continue
            
            checker = PasswordStrengthChecker(password)
            checker.print_report()


if __name__ == '__main__':
    main()


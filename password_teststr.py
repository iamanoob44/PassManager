import re
import unittest


# Automated, unit test casing for the Password Strength Checker feature in PassManager

def password_strength_check(pw):

    # Password strength is determined by these levels, with respect to the Javascript code in index.html
    # 0 - Weak
    # 1 or 2 - Medium 
    # 3 or 4 - Strong
    # 5 - Very Strong

    strength = 0
    feedback = "testing123" # dummy variable

    if len(pw) >= 10:
        strength += 1

    # Check for uppercase letters, with sufficient length for password complexity
    if re.search(r'[A-Z]', pw) and len(pw) >= 12:
        strength += 1

    # Check for lowercase letters, with sufficient length for password complexity
    if re.search(r'[a-z]', pw) and len(pw) >= 12:
        strength += 1

    # Check for numerical inputs, with sufficient length for password complexity
    if re.search(r'\d', pw) and len(pw) >= 12:
        strength += 1

    # Check for special characters, with sufficient length for password complexity
    if re.search(r'[/!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>/?~`<>]', pw) and len(pw) >= 12:
        strength += 1

    # Determine the feedback based on strength, aligning with the Javascript code in index.html
    weak_range = 0
    medium_range = [1,2]
    strong_range = [3,4]
    very_strong_range = 5

    if strength == weak_range:
        feedback = 'Password strength: Weak, consider changing.'
        colour = 'red'
    elif strength in medium_range:
        feedback = 'Password strength: Medium, encouraged to change.'
        colour = 'orange'
    elif strength in strong_range:
        feedback = 'Password strength: Strong, good and secure!'
        colour = 'yellow'
    elif strength == very_strong_range:
        feedback = 'Password strength: Very Strong, excellent and highly secure!'
        colour = 'lime'

    return {"strength": strength, "feedback": feedback, "colour": colour}



class Test(unittest.TestCase): # 8 test cases altogether!
    def test_weak_password(self):  
        result = password_strength_check("password") # password is 'password'
        self.assertEqual(result["strength"], 0)
        self.assertEqual(result["feedback"], 'Password strength: Weak, consider changing.')
        self.assertEqual(result["colour"], 'red')

    def test_weak_password2(self):  
        result = password_strength_check("manager$") # password is 'manager$'
        self.assertEqual(result["strength"], 0)
        self.assertEqual(result["feedback"], 'Password strength: Weak, consider changing.')
        self.assertEqual(result["colour"], 'red')


    def test_medium_password(self):
        result = password_strength_check("password123") # password is 'password123'
        self.assertIn(result["strength"], [1,2])
        self.assertEqual(result["feedback"], 'Password strength: Medium, encouraged to change.')
        self.assertEqual(result["colour"], 'orange')

    def test_medium_password2(self):
        result = password_strength_check("manager$12") # password is 'manager$12'
        self.assertIn(result["strength"], [1,2])
        self.assertEqual(result["feedback"], 'Password strength: Medium, encouraged to change.')
        self.assertEqual(result["colour"], 'orange')


    def test_strong_password(self):
        result = password_strength_check("password123%") # password is 'password123%'
        self.assertIn(result["strength"], [3,4])
        self.assertEqual(result["feedback"], 'Password strength: Strong, good and secure!')
        self.assertEqual(result["colour"], 'yellow')

    def test_strong_password2(self):
        result = password_strength_check("manager$1234") # password is 'manager$1234'
        self.assertIn(result["strength"], [3,4])
        self.assertEqual(result["feedback"], 'Password strength: Strong, good and secure!')
        self.assertEqual(result["colour"], 'yellow')


    def test_very_strong_password(self):
        result = password_strength_check("P@ssword123%!") # password is 'P@ssword123%!'
        self.assertEqual(result["strength"], 5)
        self.assertEqual(result["feedback"], 'Password strength: Very Strong, excellent and highly secure!')
        self.assertEqual(result["colour"], 'lime')

    
    def test_very_strong_password2(self):
        result = password_strength_check("M@nager$1234") # password is 'M@nager$1234'
        self.assertEqual(result["strength"], 5)
        self.assertEqual(result["feedback"], 'Password strength: Very Strong, excellent and highly secure!')
        self.assertEqual(result["colour"], 'lime')


if __name__ == "__main__":
    unittest.main()
# app.py

password = "admin123"

def login(user_input):
    if user_input == password:
        return True
    return False

numbers = [1,2,3]

for i in range(len(numbers)+1):
    print(numbers[i])

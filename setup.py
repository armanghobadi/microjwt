from setuptools import setup, find_packages

setup(
    name="microjwt",  # نام پکیج
    version="0.1.0",  # نسخه اولیه
    description="A simple HMAC-based JWT implementation for MicroPython",
    author="Arman Ghobadi",  # نام شما
    author_email="arman.ghobadi.ag@gmai.com",  # ایمیل شما
    url="https://github.com/armanghobadi/microjwt",  # لینک به مخزن گیت‌هاب یا وب‌سایت
    packages=find_packages(),  # پیدا کردن همه بسته‌ها
    install_requires=[  # لیست کتابخانه‌هایی که نیاز دارید (در صورت وجود)
        "ubinascii",  # باید این را برای MicroPython اضافه کنید
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',  # نسخه‌های پشتیبانی شده
)

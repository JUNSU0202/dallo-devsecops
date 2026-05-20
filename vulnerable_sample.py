import subprocess

def run_command(user_input):
    """안전: subprocess.run을 사용하여 쉘 인젝션 방지"""
    subprocess.run(["echo", user_input], check=True)
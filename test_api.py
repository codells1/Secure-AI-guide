from dotenv import load_dotenv
import anthropic

load_dotenv()
client = anthropic.Anthropic()

msg = client.messages.create(
    model="claude-sonnet-5-5",
    max_tokens=100,
    messages=[{"role": "user", "content": "연결 테스트입니다. '성공'이라고만 답해줘."}],
)
print(msg.content[0].text)
import os
from pathlib import Path
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
import ulid
from langfuse import Langfuse, observe
from langfuse.langchain import CallbackHandler


def load_env() -> Path | None:
    here = Path(__file__).resolve().parent
    candidates = [here / ".env", here.parent / ".env", here.parent.parent / ".env", Path.cwd() / ".env"]
    env_path = next((path for path in candidates if path.exists()), None)
    if env_path is not None:
        load_dotenv(dotenv_path=env_path, override=False)
    return env_path


ENV_PATH = load_env()
if not os.getenv("OPENROUTER_API_KEY"):
    searched = ", ".join(str(path) for path in [Path(__file__).resolve().parent / ".env", Path(__file__).resolve().parent.parent / ".env", Path(__file__).resolve().parent.parent.parent / ".env", Path.cwd() / ".env"])
    raise RuntimeError(
        "OPENROUTER_API_KEY is missing. Put it in a .env file and run again. "
        f"Searched: {searched}"
    )

model = ChatOpenAI(
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url="https://openrouter.ai/api/v1",
    model="gpt-4o-mini",
    temperature=0.7,
    max_tokens=50,
)

langfuse_client = Langfuse(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    host=os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse")
)


def generate_session_id():
    team = os.getenv("TEAM_NAME", "tutorial").replace(" ", "-")
    return f"{team}-{ulid.new().str}"


def invoke_langchain(model, prompt, langfuse_handler, session_id):
    messages = [HumanMessage(content=prompt)]
    response = model.invoke(messages, config={
        "callbacks": [langfuse_handler],
        "metadata": {"langfuse_session_id": session_id},
    })
    return response.content


@observe()
def run_llm_call(session_id, model, prompt):
    langfuse_handler = CallbackHandler()
    return invoke_langchain(model, prompt, langfuse_handler, session_id)


def main():
    questions = [
        "What is machine learning?",
        "Explain neural networks briefly.",
        "What is the difference between AI and ML?"
    ]

    session_id = generate_session_id()

    for i, question in enumerate(questions, 1):
        response = run_llm_call(session_id, model, question)
        print(f"[{i}/{len(questions)}] {question} -> {response[:60]}...")

    langfuse_client.flush()

    print(f"\n{len(questions)} traces sent | session: {session_id}")
    print("Check the Langfuse dashboard to verify (may take a few minutes to update).")


if __name__ == "__main__":
    main()

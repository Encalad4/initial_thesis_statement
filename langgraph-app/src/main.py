# langgraph-app/src/main.py

from src.graph.workflow import MultiAgentWorkflow


def main():
    workflow = MultiAgentWorkflow()
    
    print("Multi-Agent System Ready!")
    print("Ask me about employees, accounts, or anything else.")
    print("Type 'exit' to quit.\n")
    
    while True:
        user_input = input("\nYou: ").strip()
        
        if user_input.lower() in ['exit', 'quit']:
            print("Goodbye!")
            break
        
        if not user_input:
            continue
        
        try:
            response = workflow.run(user_input)
            
            print(f"\nAssistant: {response}")
            
        except Exception as e:
            print(f"\nError: {str(e)}")


if __name__ == "__main__":
    main()
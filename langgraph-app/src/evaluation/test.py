import json

def analyze_cwes(json_file_path):
    # Read the JSON file
    with open(json_file_path, 'r') as file:
        data = json.load(file)
    
    # Dictionary to store CWE statistics
    cwe_stats = {}
    
    # Process each case
    for case in data['cases']:
        cwe_id = case['cwe_id']
        is_vulnerable = case['real_vulnerability']
        
        # Initialize CWE entry if it doesn't exist
        if cwe_id not in cwe_stats:
            cwe_stats[cwe_id] = {
                'total': 0,
                'vulnerable_true': 0,
                'vulnerable_false': 0
            }
        
        # Update counts
        cwe_stats[cwe_id]['total'] += 1
        if is_vulnerable:
            cwe_stats[cwe_id]['vulnerable_true'] += 1
        else:
            cwe_stats[cwe_id]['vulnerable_false'] += 1
    
    # Print results
    print(f"Total distinct CWEs found: {len(cwe_stats)}")
    print("\nCWE Analysis:")
    print("-" * 60)
    print(f"{'CWE ID':<15} {'Total':<10} {'Vulnerable (True)':<20} {'Non-Vulnerable (False)':<20}")
    print("-" * 60)
    
    # Sort by CWE ID for better readability
    for cwe_id in sorted(cwe_stats.keys()):
        stats = cwe_stats[cwe_id]
        print(f"{cwe_id:<15} {stats['total']:<10} {stats['vulnerable_true']:<20} {stats['vulnerable_false']:<20}")
    
    print("-" * 60)
    
    # Summary statistics
    total_cases = len(data['cases'])
    total_vulnerable = sum(stats['vulnerable_true'] for stats in cwe_stats.values())
    total_non_vulnerable = sum(stats['vulnerable_false'] for stats in cwe_stats.values())
    
    print(f"\nSummary:")
    print(f"Total cases: {total_cases}")
    print(f"Total vulnerable: {total_vulnerable}")
    print(f"Total non-vulnerable: {total_non_vulnerable}")
    
    return cwe_stats

if __name__ == "__main__":
    # Specify the path to your JSON file
    json_file_path = "langgraph-app\src\evaluation\owasp_benchmark_java_v1_2.json"
    
    try:
        cwe_stats = analyze_cwes(json_file_path)
    except FileNotFoundError:
        print(f"Error: File '{json_file_path}' not found.")
    except json.JSONDecodeError:
        print(f"Error: File '{json_file_path}' is not valid JSON.")
    except KeyError as e:
        print(f"Error: Missing expected key in JSON structure: {e}")
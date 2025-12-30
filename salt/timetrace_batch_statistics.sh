#!/bin/bash
# timetrace_simple_statistics.sh

# ==================== Configuration Parameters ====================
INPUT_FILE="${1}"
START_THREAD="${2}"
START_EVENT_PATTERN="${3}"
END_THREAD="${4}"
END_EVENT_PATTERN="${5}"

# ==================== Helper Functions ====================
log_error() {
    echo "[ERROR] $1" >&2
}

print_help() {
    echo "Timetrace Simple Statistics Tool"
    echo ""
    echo "Usage: $0 <input_file> <start_thread> <start_event> <end_thread> <end_event>"
    echo ""
    echo "Example:"
    echo "  $0 timetrace.log T1 'update fin started' T1 'update fin finished'"
    echo ""
    exit 0
}

# Debug function
debug_log() {
    if [ "${DEBUG:-0}" -eq 1 ]; then
        echo "[DEBUG] $1" >&2
    fi
}

# ==================== Accurate Event Pairing with AWK ====================
analyze_with_awk() {
    local input_file="$1"
    local start_thread="$2"
    local start_pattern="$3"
    local end_thread="$4"
    local end_pattern="$5"
    
    awk -v start_thread="$start_thread" \
        -v start_pattern="$start_pattern" \
        -v end_thread="$end_thread" \
        -v end_pattern="$end_pattern" \
        -v debug="${DEBUG:-0}" \
    '
    BEGIN {
        # Initialize arrays
        delete start_line_num
        delete start_time
        delete start_line_content
        delete end_line_num
        delete end_time
        delete end_line_content
        delete end_used
        
        start_idx = 0
        end_idx = 0
        pair_count = 0
    }
    
    {
        line_num = NR
        current_line = $0
        
        # Debug output
        if (debug && line_num <= 10) {
            printf "[DEBUG] Line %d: %s\n", line_num, current_line > "/dev/stderr"
        }
        
        # Attempt to extract timestamp - more precise matching
        timestamp = 0
        if (match(current_line, /[0-9]+[\.][0-9]+/)) {
            timestamp = substr(current_line, RSTART, RLENGTH) + 0  # +0 converts to number
        }
        
        # Check if it is a start event
        is_start = 0
        if (start_thread != "" && $0 ~ ("^" start_thread " ")) {
            if (index($0, start_pattern) > 0) {
                is_start = 1
            }
        } else if (start_thread == "" && index($0, start_pattern) > 0) {
            # If thread not specified, match pattern only
            is_start = 1
        }
        
        if (is_start) {
            if (debug) printf "[DEBUG] Found START at line %d: %s (time=%s)\n", 
                line_num, current_line, timestamp > "/dev/stderr"
            start_line_num[start_idx] = line_num
            start_time[start_idx] = timestamp
            start_line_content[start_idx] = current_line
            start_idx++
        }
        
        # Check if it is an end event
        is_end = 0
        if (end_thread != "" && $0 ~ ("^" end_thread " ")) {
            if (index($0, end_pattern) > 0) {
                is_end = 1
            }
        } else if (end_thread == "" && index($0, end_pattern) > 0) {
            # If thread not specified, match pattern only
            is_end = 1
        }
        
        if (is_end) {
            if (debug) printf "[DEBUG] Found END at line %d: %s (time=%s)\n", 
                line_num, current_line, timestamp > "/dev/stderr"
            end_line_num[end_idx] = line_num
            end_time[end_idx] = timestamp
            end_line_content[end_idx] = current_line
            end_idx++
        }
    }
    
    END {
        if (debug) {
            printf "[DEBUG] Total starts: %d, Total ends: %d\n", 
                start_idx, end_idx > "/dev/stderr"
        }
        
        # Output statistics header
        printf "STATS:%d:%d\n", start_idx, end_idx
        
        if (start_idx == 0) {
            print "ERROR:No start events found"
            exit 1
        }
        if (end_idx == 0) {
            print "ERROR:No end events found"
            exit 1
        }
        
        # Pairing logic: For each start event, find the nearest next end event
        for (s = 0; s < start_idx; s++) {
            s_line = start_line_num[s]
            s_time = start_time[s]
            s_content = start_line_content[s]
            
            if (debug) printf "[DEBUG] Processing start %d at line %d, time %f\n", 
                s, s_line, s_time > "/dev/stderr"
            
            # Find the earliest unused end event after the start event
            best_end = -1
            best_line = 999999999
            
            for (e = 0; e < end_idx; e++) {
                # Skip used end events
                if (end_used[e] == 1) continue
                
                e_line = end_line_num[e]
                e_time = end_time[e]
                
                # Check if end event is after start event
                if (e_line > s_line) {
                    # Verify timestamp validity
                    if (e_time > 0 && s_time > 0) {
                        if (e_time > s_time) {
                            # Find the smallest line number (earliest) end event
                            if (e_line < best_line) {
                                best_end = e
                                best_line = e_line
                            }
                        }
                    } else {
                        # If no valid timestamp, use line number only
                        if (e_line < best_line) {
                            best_end = e
                            best_line = e_line
                        }
                    }
                }
            }
            
            if (best_end != -1) {
                # Successful pairing
                end_used[best_end] = 1
                
                e_content = end_line_content[best_end]
                e_time = end_time[best_end]
                
                # Calculate duration
                duration = e_time - s_time
                if (duration < 0) duration = 0
                
                # Output pairing information, using TAB as separator (more reliable)
                printf "PAIR\t%.9f\t%.9f\t%.9f\t%s\t%s\n", 
                    s_time, e_time, duration, s_content, e_content
                
                pair_count++
                
                if (debug) printf "[DEBUG] Paired start %d with end %d, duration %f\n", 
                    s, best_end, duration > "/dev/stderr"
            } else {
                if (debug) printf "[DEBUG] No end found for start %d\n", s > "/dev/stderr"
            }
        }
        
        if (debug) printf "[DEBUG] Total pairs: %d\n", pair_count > "/dev/stderr"
        
        if (pair_count == 0) {
            print "ERROR:No event pairs found"
        }
    }
    ' "$input_file"
}

# ==================== Data Verification Function ====================
verify_data() {
    echo "=== Data Verification ==="
    echo ""
    
    local pair_count=${#pairs_info[@]}
    echo "Number of pairs: $pair_count"
    
    # Verify each data set
    local error_count=0
    for ((i=0; i<pair_count; i++)); do
        IFS=$'\t' read -r start_time end_time duration_ns start_line end_line <<< "${pairs_info[i]}"
        
        # Verify timestamp format
        if [[ ! "$start_time" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            echo "Error: Group $((i+1)) start time format invalid: $start_time"
            error_count=$((error_count + 1))
        fi
        
        if [[ ! "$end_time" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            echo "Error: Group $((i+1)) end time format invalid: $end_time"
            error_count=$((error_count + 1))
        fi
        
        # Verify duration
        local calculated_duration=$(echo "$end_time - $start_time" | bc 2>/dev/null)
        local diff=$(echo "$calculated_duration - $duration_ns" | bc 2>/dev/null | awk '{if ($1<0) print -$1; else print $1}')
        
        if [ $(echo "$diff > 0.000000001" | bc -l 2>/dev/null || echo "1") = "1" ]; then
            echo "Warning: Group $((i+1)) duration calculation inconsistent"
            echo "  Original: $duration_ns, Calculated: $calculated_duration"
        fi
        
        # Verify start line contains pattern
        if [[ ! "$start_line" =~ $START_EVENT_PATTERN ]]; then
            echo "Warning: Group $((i+1)) start line doesn't contain pattern"
        fi
        
        # Verify end line contains pattern
        if [[ ! "$end_line" =~ $END_EVENT_PATTERN ]]; then
            echo "Warning: Group $((i+1)) end line doesn't contain pattern"
        fi
    done
    
    if [ $error_count -gt 0 ]; then
        echo ""
        echo "Found $error_count data errors"
    else
        echo "Data verification passed"
    fi
    echo ""
}

# ==================== Main Statistics Function ====================
simple_statistics() {
    local input_file="$1"
    local start_thread="$2"
    local start_pattern="$3"
    local end_thread="$4"
    local end_pattern="$5"
    
    # Save to global variables for verification
    START_EVENT_PATTERN="$start_pattern"
    END_EVENT_PATTERN="$end_pattern"
    
    # Check parameters
    if [ -z "$input_file" ] || [ -z "$start_thread" ] || [ -z "$start_pattern" ] \
       || [ -z "$end_thread" ] || [ -z "$end_pattern" ]; then
        print_help
    fi
    
    # Check if file exists
    if [ ! -f "$input_file" ]; then
        log_error "Input file doesn't exist: $input_file"
        exit 1
    fi
    
    echo "========================================"
    echo "      Timetrace Statistics (Fixed)     "
    echo "========================================"
    echo ""
    echo "Query Conditions:"
    echo "  Start Event: $start_thread - '$start_pattern'"
    echo "  End Event: $end_thread - '$end_pattern'"
    echo ""
    
    # ==================== 1. Extract and Pair Events ====================
    echo "Analyzing file, please wait..."
    echo ""
    
    local pair_count=0
    local start_count=0
    local end_count=0
    declare -a durations_ns
    declare -a pairs_info
    
    # Use AWK for analysis
    while IFS= read -r line; do
        if [[ "$line" == STATS:* ]]; then
            # Parse statistics
            IFS=':' read -r _ start_count end_count <<< "$line"
        elif [[ "$line" == ERROR:* ]]; then
            log_error "${line#ERROR:}"
            exit 1
        elif [[ "$line" == PAIR* ]]; then
            # Store pairing information (remove PAIR prefix)
            local pair_data="${line#PAIR$'\t'}"
            pairs_info+=("$pair_data")
            
            # Extract duration
            IFS=$'\t' read -r _ _ duration_ns _ _ <<< "$pair_data"
            durations_ns+=("$duration_ns")
        fi
    done < <(analyze_with_awk "$input_file" "$start_thread" "$start_pattern" "$end_thread" "$end_pattern")
    
    pair_count=${#pairs_info[@]}
    
    if [ $pair_count -eq 0 ]; then
        log_error "No event pairs successfully matched"
        echo "Debug suggestions:"
        echo "  1. Check if event patterns are correct"
        echo "  2. Use DEBUG=1 $0 ... to view detailed matching process"
        echo "  3. Check timestamp format"
        exit 1
    fi
    
    echo "Analysis complete: Found $start_count start events, $end_count end events, successfully paired $pair_count groups"
    echo ""
    
    # ==================== 2. Data Verification (Optional) ====================
    if [ "${VERIFY:-0}" -eq 1 ]; then
        verify_data
    fi
    
    # ==================== 3. Output Each Group's Duration ====================
    if [ "${SHOW_DETAILS:-1}" -eq 1 ]; then
        echo "=== Detailed Durations ($pair_count groups) ==="
        echo ""
        
        for ((i=0; i<pair_count; i++)); do
            IFS=$'\t' read -r start_time end_time duration_ns start_line end_line <<< "${pairs_info[i]}"
            
            # Convert to milliseconds (using more precise calculation)
            duration_ms=$(printf "%.6f" "$(echo "$duration_ns / 1000000" | bc -l)")
            
            echo "Group $((i+1)):"
            echo "Start: $start_line"
            echo "End: $end_line"
            echo "Duration: $duration_ns ns ($duration_ms ms)"
            echo "Time range: $start_time -> $end_time"
            echo ""
        done
    fi
    
    # ==================== 4. Calculate Statistical Information ====================
    echo "=== Statistical Summary ==="
    echo ""
    
    # Use bc for precise calculations
    local sum_ns=0
    local max_ns=0
    local min_ns=999999999999
    local max_idx=0
    local min_idx=0
    
    for ((i=0; i<pair_count; i++)); do
        duration="${durations_ns[i]}"
        
        # Accumulate sum
        sum_ns=$(echo "$sum_ns + $duration" | bc -l)
        
        # Compare maximum
        if [ $(echo "$duration > $max_ns" | bc -l) -eq 1 ]; then
            max_ns="$duration"
            max_idx=$i
        fi
        
        # Compare minimum
        if [ $(echo "$duration < $min_ns" | bc -l) -eq 1 ]; then
            min_ns="$duration"
            min_idx=$i
        fi
    done
    
    # Calculate average
    local avg_ns=$(echo "scale=9; $sum_ns / $pair_count" | bc -l)
    
    # Calculate median
    local median_ns=0
    if [ $pair_count -gt 0 ]; then
        # Sort to get median
        local sorted_durations=($(printf "%s\n" "${durations_ns[@]}" | sort -n))
        local mid=$((pair_count / 2))
        
        if [ $((pair_count % 2)) -eq 1 ]; then
            median_ns="${sorted_durations[mid]}"
        else
            local m1="${sorted_durations[mid-1]}"
            local m2="${sorted_durations[mid]}"
            median_ns=$(echo "scale=9; ($m1 + $m2) / 2" | bc -l)
        fi
    fi
    
    # Convert to milliseconds
    local sum_ms=$(printf "%.3f" "$(echo "$sum_ns / 1000000" | bc -l)")
    local avg_ms=$(printf "%.6f" "$(echo "$avg_ns / 1000000" | bc -l)")
    local max_ms=$(printf "%.3f" "$(echo "$max_ns / 1000000" | bc -l)")
    local min_ms=$(printf "%.3f" "$(echo "$min_ns / 1000000" | bc -l)")
    local median_ms=$(printf "%.3f" "$(echo "$median_ns / 1000000" | bc -l)")
    
    # ==================== 5. Output Statistical Results ====================
    echo "Total groups: $pair_count"
    echo ""
    
    # Maximum value information
    if [ $pair_count -gt 0 ]; then
        IFS=$'\t' read -r max_start_time max_end_time max_duration_ns max_start_line max_end_line <<< "${pairs_info[max_idx]}"
        
        echo "Maximum (Group $((max_idx+1))):"
        echo "  Duration: $max_ns ns ($max_ms ms)"
        echo "  Start: $max_start_line"
        echo "  End: $max_end_line"
        echo ""
    fi
    
    # Minimum value information
    if [ $pair_count -gt 0 ]; then
        IFS=$'\t' read -r min_start_time min_end_time min_duration_ns min_start_line min_end_line <<< "${pairs_info[min_idx]}"
        
        echo "Minimum (Group $((min_idx+1))):"
        echo "  Duration: $min_ns ns ($min_ms ms)"
        echo "  Start: $min_start_line"
        echo "  End: $min_end_line"
        echo ""
    fi
    
    echo "Average: $avg_ns ns ($avg_ms ms)"
    echo "Median: $median_ns ns ($median_ms ms)"
    echo "Total duration: $sum_ns ns ($sum_ms ms)"
    echo ""
    
    # ==================== 6. Additional Statistical Information ====================
    if [ $pair_count -gt 1 ]; then
        # Calculate standard deviation
        local variance_sum=0
        for duration in "${durations_ns[@]}"; do
            local diff=$(echo "$duration - $avg_ns" | bc -l)
            local diff_squared=$(echo "$diff * $diff" | bc -l)
            variance_sum=$(echo "$variance_sum + $diff_squared" | bc -l)
        done
        
        local variance=$(echo "scale=9; $variance_sum / ($pair_count - 1)" | bc -l)
        local stddev_ns=$(echo "sqrt($variance)" | bc -l)
        local stddev_ms=$(printf "%.6f" "$(echo "$stddev_ns / 1000000" | bc -l)")
        
        echo "Standard deviation: $stddev_ns ns ($stddev_ms ms)"
        
        # Calculate percentiles
        if [ $pair_count -ge 10 ]; then
            local p90_idx=$((pair_count * 90 / 100))
            local p95_idx=$((pair_count * 95 / 100))
            local p99_idx=$((pair_count * 99 / 100))
            
            local sorted=($(printf "%s\n" "${durations_ns[@]}" | sort -n))
            local p90_ns="${sorted[p90_idx]}"
            local p95_ns="${sorted[p95_idx]}"
            local p99_ns="${sorted[p99_idx]}"
            
            echo "P90: $(printf "%.3f" "$(echo "$p90_ns / 1000000" | bc -l)") ms"
            echo "P95: $(printf "%.3f" "$(echo "$p95_ns / 1000000" | bc -l)") ms"
            echo "P99: $(printf "%.3f" "$(echo "$p99_ns / 1000000" | bc -l)") ms"
        fi
        echo ""
    fi
    
    # ==================== 7. Output Summary Information ====================
    echo "=== Summary Information ==="
    echo ""
    echo "Total start events: $start_count"
    echo "Total end events: $end_count"
    echo "Successfully paired: $pair_count"
    
    local unused_starts=$((start_count - pair_count))
    local unused_ends=$((end_count - pair_count))
    
    if [ $unused_starts -gt 0 ]; then
        echo "Unpaired start events: $unused_starts"
    fi
    
    if [ $unused_ends -gt 0 ]; then
        echo "Unused end events: $unused_ends"
    fi
    
    if [ $unused_starts -eq 0 ] && [ $unused_ends -eq 0 ]; then
        echo "Perfect match: All start and end events successfully paired"
    fi
    
    echo ""
    echo "========================================"
}

# ==================== Debug Mode ====================
debug_mode() {
    echo "=== Debug Mode ==="
    echo "Input file: $1"
    echo "Start thread: $2, Start pattern: $3"
    echo "End thread: $4, End pattern: $5"
    echo ""
    
    DEBUG=1 analyze_with_awk "$1" "$2" "$3" "$4" "$5"
    
    echo ""
    echo "Debug output completed"
}

# ==================== Main Execution Flow ====================
main() {
    # Check parameters
    if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ $# -lt 1 ]; then
        print_help
    fi
    
    # Debug mode
    if [ "$1" = "--debug" ]; then
        shift
        if [ $# -lt 5 ]; then
            echo "Debug mode requires all 5 parameters"
            print_help
        fi
        debug_mode "$@"
        exit 0
    fi
    
    # Verification mode
    if [ "$1" = "--verify" ]; then
        shift
        VERIFY=1 simple_statistics "$@"
        exit 0
    fi
    
    # Silent mode (only show summary)
    if [ "$1" = "--quiet" ]; then
        shift
        SHOW_DETAILS=0 simple_statistics "$@"
        exit 0
    fi
    
    # Normal mode
    if [ $# -lt 5 ]; then
        print_help
    fi
    
    simple_statistics "$@"
}

# Execute main function
main "$@"
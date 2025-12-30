#!/bin/bash
# timetrace_simple_statistics.sh - 修复版批量统计

# ==================== 配置参数 ====================
INPUT_FILE="${1}"
START_THREAD="${2}"
START_EVENT_PATTERN="${3}"
END_THREAD="${4}"
END_EVENT_PATTERN="${5}"

# ==================== 辅助函数 ====================
log_error() {
    echo "[ERROR] $1" >&2
}

print_help() {
    echo "Timetrace简化统计工具"
    echo ""
    echo "用法: $0 <输入文件> <开始线程> <开始事件> <结束线程> <结束事件>"
    echo ""
    echo "示例:"
    echo "  $0 timetrace.log T1 'update fin started' T1 'update fin finished'"
    echo ""
    exit 0
}

# 调试函数
debug_log() {
    if [ "${DEBUG:-0}" -eq 1 ]; then
        echo "[DEBUG] $1" >&2
    fi
}

# ==================== 使用AWK进行准确的事件配对 ====================
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
        # 初始化数组
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
        
        # 调试输出
        if (debug && line_num <= 10) {
            printf "[DEBUG] Line %d: %s\n", line_num, current_line > "/dev/stderr"
        }
        
        # 尝试提取时间戳 - 更精确的匹配
        timestamp = 0
        if (match(current_line, /[0-9]+[\.][0-9]+/)) {
            timestamp = substr(current_line, RSTART, RLENGTH) + 0  # +0 转换为数字
        }
        
        # 检查是否为开始事件
        is_start = 0
        if (start_thread != "" && $0 ~ ("^" start_thread " ")) {
            if (index($0, start_pattern) > 0) {
                is_start = 1
            }
        } else if (start_thread == "" && index($0, start_pattern) > 0) {
            # 如果没有指定线程，只匹配模式
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
        
        # 检查是否为结束事件
        is_end = 0
        if (end_thread != "" && $0 ~ ("^" end_thread " ")) {
            if (index($0, end_pattern) > 0) {
                is_end = 1
            }
        } else if (end_thread == "" && index($0, end_pattern) > 0) {
            # 如果没有指定线程，只匹配模式
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
        
        # 输出统计信息头
        printf "STATS:%d:%d\n", start_idx, end_idx
        
        if (start_idx == 0) {
            print "ERROR:No start events found"
            exit 1
        }
        if (end_idx == 0) {
            print "ERROR:No end events found"
            exit 1
        }
        
        # 配对逻辑：对于每个开始事件，找到最近的下一个结束事件
        for (s = 0; s < start_idx; s++) {
            s_line = start_line_num[s]
            s_time = start_time[s]
            s_content = start_line_content[s]
            
            if (debug) printf "[DEBUG] Processing start %d at line %d, time %f\n", 
                s, s_line, s_time > "/dev/stderr"
            
            # 寻找在开始事件之后且未使用的最早结束事件
            best_end = -1
            best_line = 999999999
            
            for (e = 0; e < end_idx; e++) {
                # 跳过已使用的结束事件
                if (end_used[e] == 1) continue
                
                e_line = end_line_num[e]
                e_time = end_time[e]
                
                # 检查结束事件是否在开始事件之后
                if (e_line > s_line) {
                    # 验证时间戳有效性
                    if (e_time > 0 && s_time > 0) {
                        if (e_time > s_time) {
                            # 找到行号最小的（最早的）结束事件
                            if (e_line < best_line) {
                                best_end = e
                                best_line = e_line
                            }
                        }
                    } else {
                        # 如果没有有效时间戳，只使用行号
                        if (e_line < best_line) {
                            best_end = e
                            best_line = e_line
                        }
                    }
                }
            }
            
            if (best_end != -1) {
                # 配对成功
                end_used[best_end] = 1
                
                e_content = end_line_content[best_end]
                e_time = end_time[best_end]
                
                # 计算持续时间
                duration = e_time - s_time
                if (duration < 0) duration = 0
                
                # 输出配对信息，使用 TAB 作为分隔符（更可靠）
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

# ==================== 验证测试函数 ====================
verify_data() {
    echo "=== 数据验证 ==="
    echo ""
    
    local pair_count=${#pairs_info[@]}
    echo "配对数量: $pair_count"
    
    # 验证每组数据
    local error_count=0
    for ((i=0; i<pair_count; i++)); do
        IFS=$'\t' read -r start_time end_time duration_ns start_line end_line <<< "${pairs_info[i]}"
        
        # 验证时间戳
        if [[ ! "$start_time" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            echo "错误: 第 $((i+1)) 组开始时间格式无效: $start_time"
            error_count=$((error_count + 1))
        fi
        
        if [[ ! "$end_time" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            echo "错误: 第 $((i+1)) 组结束时间格式无效: $end_time"
            error_count=$((error_count + 1))
        fi
        
        # 验证持续时间
        local calculated_duration=$(echo "$end_time - $start_time" | bc 2>/dev/null)
        local diff=$(echo "$calculated_duration - $duration_ns" | bc 2>/dev/null | awk '{if ($1<0) print -$1; else print $1}')
        
        if [ $(echo "$diff > 0.000000001" | bc -l 2>/dev/null || echo "1") = "1" ]; then
            echo "警告: 第 $((i+1)) 组持续时间计算不一致"
            echo "  原始: $duration_ns, 计算: $calculated_duration"
        fi
        
        # 验证开始行包含模式
        if [[ ! "$start_line" =~ $START_EVENT_PATTERN ]]; then
            echo "警告: 第 $((i+1)) 组开始行不包含模式"
        fi
        
        # 验证结束行包含模式
        if [[ ! "$end_line" =~ $END_EVENT_PATTERN ]]; then
            echo "警告: 第 $((i+1)) 组结束行不包含模式"
        fi
    done
    
    if [ $error_count -gt 0 ]; then
        echo ""
        echo "发现 $error_count 个数据错误"
    else
        echo "数据验证通过"
    fi
    echo ""
}

# ==================== 主统计函数 ====================
simple_statistics() {
    local input_file="$1"
    local start_thread="$2"
    local start_pattern="$3"
    local end_thread="$4"
    local end_pattern="$5"
    
    # 保存到全局变量用于验证
    START_EVENT_PATTERN="$start_pattern"
    END_EVENT_PATTERN="$end_pattern"
    
    # 检查参数
    if [ -z "$input_file" ] || [ -z "$start_thread" ] || [ -z "$start_pattern" ] \
       || [ -z "$end_thread" ] || [ -z "$end_pattern" ]; then
        print_help
    fi
    
    # 检查文件是否存在
    if [ ! -f "$input_file" ]; then
        log_error "输入文件不存在: $input_file"
        exit 1
    fi
    
    echo "========================================"
    echo "      Timetrace统计结果 (修复版)     "
    echo "========================================"
    echo ""
    echo "查询条件:"
    echo "  开始事件: $start_thread - '$start_pattern'"
    echo "  结束事件: $end_thread - '$end_pattern'"
    echo ""
    
    # ==================== 1. 提取和配对事件 ====================
    echo "正在分析文件，请稍候..."
    echo ""
    
    local pair_count=0
    local start_count=0
    local end_count=0
    declare -a durations_ns
    declare -a pairs_info
    
    # 使用AWK分析
    while IFS= read -r line; do
        if [[ "$line" == STATS:* ]]; then
            # 解析统计信息
            IFS=':' read -r _ start_count end_count <<< "$line"
        elif [[ "$line" == ERROR:* ]]; then
            log_error "${line#ERROR:}"
            exit 1
        elif [[ "$line" == PAIR* ]]; then
            # 存储配对信息（去掉PAIR前缀）
            local pair_data="${line#PAIR$'\t'}"
            pairs_info+=("$pair_data")
            
            # 提取持续时间
            IFS=$'\t' read -r _ _ duration_ns _ _ <<< "$pair_data"
            durations_ns+=("$duration_ns")
        fi
    done < <(analyze_with_awk "$input_file" "$start_thread" "$start_pattern" "$end_thread" "$end_pattern")
    
    pair_count=${#pairs_info[@]}
    
    if [ $pair_count -eq 0 ]; then
        log_error "未成功配对任何事件"
        echo "调试建议："
        echo "  1. 检查事件模式是否正确"
        echo "  2. 使用 DEBUG=1 $0 ... 查看详细匹配过程"
        echo "  3. 检查时间戳格式"
        exit 1
    fi
    
    echo "分析完成: 找到 $start_count 个开始事件, $end_count 个结束事件, 成功配对 $pair_count 组"
    echo ""
    
    # ==================== 2. 数据验证（可选） ====================
    if [ "${VERIFY:-0}" -eq 1 ]; then
        verify_data
    fi
    
    # ==================== 3. 输出每组耗时 ====================
    if [ "${SHOW_DETAILS:-1}" -eq 1 ]; then
        echo "=== 详细耗时 ($pair_count 组) ==="
        echo ""
        
        for ((i=0; i<pair_count; i++)); do
            IFS=$'\t' read -r start_time end_time duration_ns start_line end_line <<< "${pairs_info[i]}"
            
            # 转换为毫秒（使用更精确的计算）
            duration_ms=$(printf "%.6f" "$(echo "$duration_ns / 1000000" | bc -l)")
            
            echo "第 $((i+1)) 组:"
            echo "开始: $start_line"
            echo "结束: $end_line"
            echo "耗时: $duration_ns ns ($duration_ms ms)"
            echo "时间范围: $start_time -> $end_time"
            echo ""
        done
    fi
    
    # ==================== 4. 计算统计信息 ====================
    echo "=== 统计摘要 ==="
    echo ""
    
    # 使用bc进行精确计算
    local sum_ns=0
    local max_ns=0
    local min_ns=999999999999
    local max_idx=0
    local min_idx=0
    
    for ((i=0; i<pair_count; i++)); do
        duration="${durations_ns[i]}"
        
        # 累加总和
        sum_ns=$(echo "$sum_ns + $duration" | bc -l)
        
        # 比较最大值
        if [ $(echo "$duration > $max_ns" | bc -l) -eq 1 ]; then
            max_ns="$duration"
            max_idx=$i
        fi
        
        # 比较最小值
        if [ $(echo "$duration < $min_ns" | bc -l) -eq 1 ]; then
            min_ns="$duration"
            min_idx=$i
        fi
    done
    
    # 计算平均值
    local avg_ns=$(echo "scale=9; $sum_ns / $pair_count" | bc -l)
    
    # 计算中位数
    local median_ns=0
    if [ $pair_count -gt 0 ]; then
        # 排序获取中位数
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
    
    # 转换为毫秒
    local sum_ms=$(printf "%.3f" "$(echo "$sum_ns / 1000000" | bc -l)")
    local avg_ms=$(printf "%.6f" "$(echo "$avg_ns / 1000000" | bc -l)")
    local max_ms=$(printf "%.3f" "$(echo "$max_ns / 1000000" | bc -l)")
    local min_ms=$(printf "%.3f" "$(echo "$min_ns / 1000000" | bc -l)")
    local median_ms=$(printf "%.3f" "$(echo "$median_ns / 1000000" | bc -l)")
    
    # ==================== 5. 输出统计结果 ====================
    echo "总组数: $pair_count"
    echo ""
    
    # 最大值信息
    if [ $pair_count -gt 0 ]; then
        IFS=$'\t' read -r max_start_time max_end_time max_duration_ns max_start_line max_end_line <<< "${pairs_info[max_idx]}"
        
        echo "最大值 (第 $((max_idx+1)) 组):"
        echo "  耗时: $max_ns ns ($max_ms ms)"
        echo "  开始: $max_start_line"
        echo "  结束: $max_end_line"
        echo ""
    fi
    
    # 最小值信息
    if [ $pair_count -gt 0 ]; then
        IFS=$'\t' read -r min_start_time min_end_time min_duration_ns min_start_line min_end_line <<< "${pairs_info[min_idx]}"
        
        echo "最小值 (第 $((min_idx+1)) 组):"
        echo "  耗时: $min_ns ns ($min_ms ms)"
        echo "  开始: $min_start_line"
        echo "  结束: $min_end_line"
        echo ""
    fi
    
    echo "平均值: $avg_ns ns ($avg_ms ms)"
    echo "中位数: $median_ns ns ($median_ms ms)"
    echo "总耗时: $sum_ns ns ($sum_ms ms)"
    echo ""
    
    # ==================== 6. 额外统计信息 ====================
    if [ $pair_count -gt 1 ]; then
        # 计算标准差
        local variance_sum=0
        for duration in "${durations_ns[@]}"; do
            local diff=$(echo "$duration - $avg_ns" | bc -l)
            local diff_squared=$(echo "$diff * $diff" | bc -l)
            variance_sum=$(echo "$variance_sum + $diff_squared" | bc -l)
        done
        
        local variance=$(echo "scale=9; $variance_sum / ($pair_count - 1)" | bc -l)
        local stddev_ns=$(echo "sqrt($variance)" | bc -l)
        local stddev_ms=$(printf "%.6f" "$(echo "$stddev_ns / 1000000" | bc -l)")
        
        echo "标准差: $stddev_ns ns ($stddev_ms ms)"
        
        # 计算百分位数
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
    
    # ==================== 7. 输出汇总信息 ====================
    echo "=== 汇总信息 ==="
    echo ""
    echo "开始事件总数: $start_count"
    echo "结束事件总数: $end_count"
    echo "成功配对数: $pair_count"
    
    local unused_starts=$((start_count - pair_count))
    local unused_ends=$((end_count - pair_count))
    
    if [ $unused_starts -gt 0 ]; then
        echo "未配对的开始事件: $unused_starts"
    fi
    
    if [ $unused_ends -gt 0 ]; then
        echo "未使用的结束事件: $unused_ends"
    fi
    
    if [ $unused_starts -eq 0 ] && [ $unused_ends -eq 0 ]; then
        echo "完美匹配: 所有开始和结束事件都成功配对"
    fi
    
    echo ""
    echo "========================================"
}

# ==================== 调试模式 ====================
debug_mode() {
    echo "=== 调试模式 ==="
    echo "输入文件: $1"
    echo "开始线程: $2, 开始模式: $3"
    echo "结束线程: $4, 结束模式: $5"
    echo ""
    
    DEBUG=1 analyze_with_awk "$1" "$2" "$3" "$4" "$5"
    
    echo ""
    echo "调试输出完成"
}

# ==================== 主执行流程 ====================
main() {
    # 检查参数
    if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ $# -lt 1 ]; then
        print_help
    fi
    
    # 调试模式
    if [ "$1" = "--debug" ]; then
        shift
        if [ $# -lt 5 ]; then
            echo "调试模式需要完整的5个参数"
            print_help
        fi
        debug_mode "$@"
        exit 0
    fi
    
    # 验证模式
    if [ "$1" = "--verify" ]; then
        shift
        VERIFY=1 simple_statistics "$@"
        exit 0
    fi
    
    # 静默模式（只显示摘要）
    if [ "$1" = "--quiet" ]; then
        shift
        SHOW_DETAILS=0 simple_statistics "$@"
        exit 0
    fi
    
    # 正常模式
    if [ $# -lt 5 ]; then
        print_help
    fi
    
    simple_statistics "$@"
}

# 执行主函数
main "$@"
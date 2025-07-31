#!/usr/bin/python3
"""
Generates a plot illustrating the amortized cost per key for updating
the state root in the SALT trie.

This script calculates the cost for a range of batch sizes (N) and plots
the amortized cost (in ECMuls) against N on a log scale. It demonstrates
how batching makes state updates more efficient as the batch size increases.
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


def unique_bins(balls: int, bins: int) -> float:
    """
    Calculates the expected number of unique bins hit when throwing L balls
    into B bins, assuming a uniform random distribution.

    This is a classic "balls-into-bins" or "coupon collector" problem variant.

    Args:
        balls: The number of items being distributed (e.g., updated keys).
        bins: The number of available containers (e.g., parent nodes).

    Returns:
        The expected number of unique bins that contain at least one ball.
    """
    if bins <= 0:
        return 0
    # The formula for the expected number of non-empty bins is B * (1 - (1 - 1/B)^L)
    return bins * (1 - (1 - 1 / bins) ** balls)


def propagation_cost(n_updates: int) -> float:
    """
    Calculates the total number of unique trie nodes (except the root) affected by
    a batch update of a given size.

    This models the propagation of changes from the leaves (Level 3) up to
    the root (Level 0) in the 4-level, 256-ary SALT trie.

    Args:
        n_updates: The number of keys being updated in the batch.

    Returns:
        The total expected number of unique internal nodes that incurs ECMul ops.
    """
    # Calculate how many unique nodes at Level 3 are affected.
    bins_l3 = 256**3  # 16,777,216 nodes
    n_l3_affected = unique_bins(n_updates, bins_l3)

    # Calculate how many unique nodes at Level 2 are affected.
    bins_l2 = 256**2  # 65,536 nodes
    n_l2_affected = unique_bins(n_l3_affected, bins_l2)

    # Calculate how many unique nodes at Level 1 are affected.
    bins_l1 = 256  # 256 nodes
    n_l1_affected = unique_bins(n_l2_affected, bins_l1)

    # Doesn't matter care if the root (Level 0) is affected as
    # because it has no parent node
    # n_l0_affected = 1 if n_l1_affected > 0 else 0

    return n_l3_affected + n_l2_affected + n_l1_affected


# --- Main Script Execution ---

if __name__ == "__main__":
    # 1. Define the range for N (number of updated keys) on a log scale.
    N_values = np.logspace(0, 6, 500)  # From 1 to 1,000,000

    # 2. Calculate the costs for each value of N.
    # The amortized cost is 1 (for the kv update) + the amortized propagation cost.
    propagation_costs = np.array([propagation_cost(n) for n in N_values])
    amortized_costs = 1 + propagation_costs / N_values

    # 3. Set up and generate the plot.
    plt.style.use('seaborn-v0_8-whitegrid')
    fig, ax = plt.subplots(figsize=(12, 8))

    # Plot the primary data curve.
    ax.plot(N_values, amortized_costs, label='Amortized Cost per Key', color='royalblue', linewidth=2.5)

    # Use a logarithmic scale for the x-axis to show the full range effectively.
    ax.set_xscale('log')

    # Plot horizontal lines showing the asymptotic cost regimes.
    ax.axhline(y=4, color='darkorange', linestyle='--', linewidth=1.5, label='~4 (Small Batches)')
    ax.axhline(y=3, color='green', linestyle='--', linewidth=1.5, label='~3 (Medium Batches)')
    ax.axhline(y=2, color='firebrick', linestyle='--', linewidth=1.5, label='2 (Theoretical Minimum)')

    # Add text annotations to clarify the cost regimes on the plot.
    ax.text(40, 3.8, 'Cost ≈ 4', va='bottom', ha='center', color='darkorange', fontsize=12)
    ax.text(3000, 2.9, 'Cost ≈ 3', va='bottom', ha='center', color='green', fontsize=12)
    ax.text(1e5, 2.1, 'Cost → 2', va='bottom', ha='center', color='firebrick', fontsize=12)

    # Set plot titles and axis labels.
    ax.set_title('Cost of Updating State Root in SALT', fontsize=18, pad=20)
    ax.set_xlabel('Number of Updated Keys (N) - Log Scale', fontsize=14, labelpad=15)
    ax.set_ylabel('Amortized Cost per Key (ECMul)', fontsize=14, labelpad=15)

    # Customize tick labels for readability.
    ax.tick_params(axis='both', which='major', labelsize=12)
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda y, _: '{:g}'.format(y)))
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter('%.2f'))

    # Enable grid lines for both major and minor ticks.
    ax.yaxis.set_major_locator(mticker.MultipleLocator(0.5))
    ax.yaxis.set_minor_locator(mticker.MultipleLocator(0.1))
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)

    # Set axis limits and display the legend.
    ax.set_ylim(1.9, 4.0)
    ax.set_xlim(1, 1e6)
    ax.legend(fontsize=12, loc='upper right')

    # Ensure the layout is clean and save the figure.
    plt.tight_layout()
    plt.savefig('salt_state_root_update_cost_graph.png', dpi=600)

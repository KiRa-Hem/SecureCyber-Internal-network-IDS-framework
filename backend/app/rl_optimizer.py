import numpy as np
from typing import Dict, List, Any, Tuple
import random
import json
import os

class RLOptimizer:
    def __init__(self, state_size: int = 10, action_size: int = 5):
        self.state_size = state_size
        self.action_size = action_size
        self.q_table = {}
        self.learning_rate = 0.1
        self.discount_factor = 0.95
        self.exploration_rate = 0.1
        self.model_path = "models/rl_optimizer.json"
        self.load_model()
    
    def state_to_key(self, state: np.ndarray) -> str:
        """Convert state array to a string key for Q-table."""
        return ','.join([str(int(x)) for x in state])
    
    def get_q_value(self, state: np.ndarray, action: int) -> float:
        """Get Q-value for a state-action pair."""
        state_key = self.state_to_key(state)
        if state_key not in self.q_table:
            self.q_table[state_key] = [0.0] * self.action_size
        return self.q_table[state_key][action]
    
    def set_q_value(self, state: np.ndarray, action: int, value: float):
        """Set Q-value for a state-action pair."""
        state_key = self.state_to_key(state)
        if state_key not in self.q_table:
            self.q_table[state_key] = [0.0] * self.action_size
        self.q_table[state_key][action] = value
    
    def choose_action(self, state: np.ndarray) -> int:
        """Choose action using epsilon-greedy policy."""
        if random.random() < self.exploration_rate:
            return random.randint(0, self.action_size - 1)
        else:
            q_values = [self.get_q_value(state, action) for action in range(self.action_size)]
            return np.argmax(q_values)
    
    def update_q_value(self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray):
        """Update Q-value using Q-learning algorithm."""
        current_q = self.get_q_value(state, action)
        max_next_q = max([self.get_q_value(next_state, a) for a in range(self.action_size)])
        new_q = current_q + self.learning_rate * (reward + self.discount_factor * max_next_q - current_q)
        self.set_q_value(state, action, new_q)
    
    def extract_state(self, network_stats: Dict[str, Any]) -> np.ndarray:
        """Extract state from network statistics."""
        state = [
            network_stats.get('packets_per_second', 0) / 1000,  # Normalized packet rate
            network_stats.get('alert_rate', 0) / 10,        # Normalized alert rate
            network_stats.get('blocked_ips', 0) / 100,      # Normalized blocked IPs
            network_stats.get('active_connections', 0) / 50,  # Normalized connections
            network_stats.get('cpu_usage', 0) / 100,       # Normalized CPU usage
            network_stats.get('memory_usage', 0) / 100,    # Normalized memory usage
            network_stats.get('disk_usage', 0) / 100,      # Normalized disk usage
            network_stats.get('network_latency', 0) / 100,  # Normalized latency
            network_stats.get('error_rate', 0) / 100        # Normalized error rate
        ]
        
        # Discretize continuous values
        return np.array([int(min(9, max(0, int(x * 10)))) for x in state])
    
    def get_reward(self, state: np.ndarray, action: int, next_state: np.ndarray) -> float:
        """Calculate reward based on state transition and action."""
        # Define reward structure
        reward = 0
        
        # Penalize high alert rates
        if next_state[1] > 5:  # High alert rate
            reward -= 10
        
        # Reward for blocking malicious IPs
        if action == 1 and next_state[2] > 0:  # Block action and blocked IPs increased
            reward += 5
        
        # Penalize high resource usage
        if next_state[5] > 8 or next_state[6] > 8:  # High CPU or memory usage
            reward -= 5
        
        # Reward for maintaining low alert rates
        if next_state[1] < 2:  # Low alert rate
            reward += 2
        
        return reward
    
    def optimize(self, network_stats: Dict[str, Any], iterations: int = 100) -> Dict[str, Any]:
        """Run optimization for given network statistics."""
        state = self.extract_state(network_stats)
        total_reward = 0
        
        for _ in range(iterations):
            # Choose action
            action = self.choose_action(state)
            
            # Simulate next state (simplified)
            next_state = self.simulate_next_state(state, action)
            
            # Calculate reward
            reward = self.get_reward(state, action, next_state)
            total_reward += reward
            
            # Update Q-value
            self.update_q_value(state, action, reward, next_state)
            
            # Update state
            state = next_state
        
        # Get optimal action
        optimal_action = np.argmax([self.get_q_value(state, a) for a in range(self.action_size)])
        
        # Save model
        self.save_model()
        
        return {
            "optimal_action": int(optimal_action),
            "total_reward": total_reward,
            "q_table_size": len(self.q_table)
        }
    
    def simulate_next_state(self, state: np.ndarray, action: int) -> np.ndarray:
        """Simulate next state based on action."""
        next_state = state.copy()
        
        # Simulate effect of actions
        if action == 0:  # No action
            pass
        elif action == 1:  # Block IP
            next_state[2] = min(9, next_state[2] + 2)  # Increase blocked IPs
        elif action == 2:  # Throttle traffic
            next_state[0] = max(0, next_state[0] - 1)  # Decrease packet rate
        elif action == 3:  # Scale resources
            next_state[5] = max(0, next_state[5] - 1)  # Decrease CPU usage
            next_state[6] = max(0, next_state[6] - 1)  # Decrease memory usage
        elif action == 4:  # Isolate node
            next_state[0] = max(0, next_state[0] - 2)  # Decrease packet rate
            next_state[1] = max(0, next_state[1] - 1)  # Decrease alert rate
        
        # Add some randomness
        for i in range(len(next_state)):
            if random.random() < 0.1:  # 10% chance of random change
                next_state[i] = max(0, min(9, next_state[i] + random.choice([-1, 1])))
        
        return next_state
    
    def save_model(self):
        """Save Q-table to file."""
        try:
            with open(self.model_path, 'w') as f:
                json.dump(self.q_table, f)
        except Exception as e:
            print(f"Error saving RL model: {e}")
    
    def load_model(self):
        """Load Q-table from file."""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'r') as f:
                    self.q_table = json.load(f)
        except Exception as e:
            print(f"Error loading RL model: {e}")
            self.q_table = {}
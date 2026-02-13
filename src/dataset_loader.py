"""
Dataset Loader - Load and process HCRL Car Hacking Dataset
"""

import pandas as pd
import numpy as np
import os
from collections import defaultdict
from typing import Optional, Tuple


class HCRLDataset:
    """Load and process HCRL Car Hacking Dataset"""
    
    def __init__(self, base_path: str):
        """
        Initialize dataset loader
        
        Args:
            base_path: Path to folder containing HCRL .txt files
        """
        self.base_path = base_path
        self.datasets = {}
        self.feature_extractors = []
        
        # Verify path exists
        if not os.path.exists(base_path):
            raise ValueError(f"Dataset path does not exist: {base_path}")
    
    def load_dataset(self, dataset_type: str = 'normal') -> pd.DataFrame:
        """
        Load a specific dataset
        
        Args:
            dataset_type: One of 'normal', 'dos', 'fuzzy', 'impersonation', 'all'
        
        Returns:
            DataFrame with CAN messages
        """
        
        file_map = {
            'normal': 'Attack_free_dataset.txt',
            'dos': 'DoS_attack_dataset.txt',
            'fuzzy': 'Fuzzy_attack_dataset.txt',
            'impersonation': 'Impersonatio...ck_dataset.txt'  # Replace with actual filename
        }
        
        # Handle 'all' option
        if dataset_type == 'all':
            print("Loading all datasets...")
            for dtype in ['normal', 'dos', 'fuzzy', 'impersonation']:
                try:
                    self.load_dataset(dtype)
                except Exception as e:
                    print(f"Warning: Could not load {dtype}: {e}")
            return self.datasets
        
        # Get filename
        if dataset_type not in file_map:
            raise ValueError(f"Unknown dataset type: {dataset_type}")
        
        filename = file_map[dataset_type]
        filepath = os.path.join(self.base_path, filename)
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dataset file not found: {filepath}")
        
        print(f"Loading {dataset_type} dataset from {filename}...")
        
        # Column names for HCRL format
        columns = [
            'Timestamp', 'CAN_ID', 'DLC',
            'Data0', 'Data1', 'Data2', 'Data3',
            'Data4', 'Data5', 'Data6', 'Data7',
            'Flag'
        ]
        
        # Read the dataset
        # HCRL files are space-separated
        df = pd.read_csv(
            filepath,
            sep=r'\s+',  # Whitespace separator
            names=columns,
            header=None,
            engine='python'
        )
        
        # Convert hex strings to integers
        df['CAN_ID'] = df['CAN_ID'].apply(lambda x: int(str(x), 16))
        
        for i in range(8):
            col = f'Data{i}'
            df[col] = df[col].apply(lambda x: int(str(x), 16) if pd.notna(x) else 0)
        
        # Add label column (0 = normal, 1 = attack)
        df['Label'] = 0 if dataset_type == 'normal' else 1
        df['AttackType'] = dataset_type
        
        # Store in dictionary
        self.datasets[dataset_type] = df
        
        # Print summary
        print(f"✓ Loaded {len(df):,} messages")
        print(f"  Unique CAN IDs: {df['CAN_ID'].nunique()}")
        print(f"  Time span: {df['Timestamp'].max() - df['Timestamp'].min():.2f} seconds")
        print(f"  Message rate: {len(df) / (df['Timestamp'].max() - df['Timestamp'].min()):.2f} msg/s\n")
        
        return df
    
    def get_statistics(self, dataset_type: str = 'normal') -> dict:
        """Get detailed statistics about a dataset"""
        
        if dataset_type not in self.datasets:
            self.load_dataset(dataset_type)
        
        df = self.datasets[dataset_type]
        
        # Calculate inter-message intervals
        df_sorted = df.sort_values('Timestamp')
        intervals = df_sorted['Timestamp'].diff().dropna()
        
        stats = {
            'dataset_type': dataset_type,
            'total_messages': len(df),
            'unique_can_ids': df['CAN_ID'].nunique(),
            'time_duration': df['Timestamp'].max() - df['Timestamp'].min(),
            'avg_message_rate': len(df) / (df['Timestamp'].max() - df['Timestamp'].min()),
            'most_common_ids': df['CAN_ID'].value_counts().head(10).to_dict(),
            'avg_interval_ms': intervals.mean() * 1000,
            'median_interval_ms': intervals.median() * 1000,
            'min_interval_ms': intervals.min() * 1000,
            'max_interval_ms': intervals.max() * 1000,
        }
        
        return stats
    
    def print_statistics(self, dataset_type: str = 'normal'):
        """Print formatted statistics"""
        stats = self.get_statistics(dataset_type)
        
        print(f"\n{'='*70}")
        print(f"STATISTICS FOR {dataset_type.upper()} DATASET")
        print(f"{'='*70}")
        print(f"Total Messages:        {stats['total_messages']:,}")
        print(f"Unique CAN IDs:        {stats['unique_can_ids']}")
        print(f"Duration:              {stats['time_duration']:.2f} seconds")
        print(f"Avg Message Rate:      {stats['avg_message_rate']:.2f} msg/s")
        print(f"Avg Inter-msg Interval: {stats['avg_interval_ms']:.4f} ms")
        print(f"Median Interval:       {stats['median_interval_ms']:.4f} ms")
        print(f"Min Interval:          {stats['min_interval_ms']:.6f} ms")
        print(f"Max Interval:          {stats['max_interval_ms']:.2f} ms")
        
        print(f"\nTop 10 Most Common CAN IDs:")
        for can_id, count in list(stats['most_common_ids'].items())[:10]:
            percentage = (count / stats['total_messages']) * 100
            print(f"  0x{can_id:03X}: {count:8,} messages ({percentage:5.2f}%)")
        
        print(f"{'='*70}\n")
    
    def extract_features(self, df: Optional[pd.DataFrame] = None, 
                        window_size: int = 10) -> Tuple[np.ndarray, np.ndarray]:
        """
        Extract features for machine learning
        
        Args:
            df: DataFrame to extract from (or use last loaded)
            window_size: Number of messages to use as context
        
        Returns:
            (features, labels) as numpy arrays
        """
        
        if df is None:
            if not self.datasets:
                raise ValueError("No dataset loaded")
            df = list(self.datasets.values())[0]
        
        print(f"Extracting features with window size {window_size}...")
        
        features = []
        labels = []
        
        # Sort by timestamp
        df = df.sort_values('Timestamp').reset_index(drop=True)
        
        for i in range(len(df) - window_size):
            window = df.iloc[i:i+window_size]
            
            # Feature 1-2: CAN ID statistics
            unique_ids = window['CAN_ID'].nunique()
            most_common_id = window['CAN_ID'].mode()[0] if len(window) > 0 else 0
            
            # Feature 3-4: Timing features
            time_diffs = window['Timestamp'].diff().dropna()
            avg_time_diff = time_diffs.mean() if len(time_diffs) > 0 else 0
            std_time_diff = time_diffs.std() if len(time_diffs) > 1 else 0
            
            # Feature 5-6: Data statistics
            data_cols = ['Data0', 'Data1', 'Data2', 'Data3']
            data_values = window[data_cols].values.flatten()
            data_mean = np.mean(data_values)
            data_std = np.std(data_values)
            
            # Feature 7: Data entropy (randomness)
            entropy = self._calculate_entropy(data_values)
            
            # Feature 8: DLC average
            avg_dlc = window['DLC'].mean()
            
            # Feature 9-10: Message frequency
            time_span = window['Timestamp'].max() - window['Timestamp'].min()
            message_rate = len(window) / time_span if time_span > 0 else 0
            
            # Feature 11: ID concentration (how much one ID dominates)
            id_concentration = window['CAN_ID'].value_counts().iloc[0] / len(window)
            
            feature_vector = [
                unique_ids,
                most_common_id,
                avg_time_diff,
                std_time_diff,
                data_mean,
                data_std,
                entropy,
                avg_dlc,
                message_rate,
                id_concentration
            ]
            
            features.append(feature_vector)
            labels.append(df.iloc[i]['Label'])
            
            if i % 10000 == 0 and i > 0:
                print(f"  Processed {i:,}/{len(df):,} messages...")
        
        features = np.array(features)
        labels = np.array(labels)
        
        print(f"✓ Extracted {len(features):,} feature vectors")
        print(f"  Feature shape: {features.shape}")
        print(f"  Normal samples: {np.sum(labels == 0):,}")
        print(f"  Attack samples: {np.sum(labels == 1):,}\n")
        
        return features, labels
    
    def _calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy"""
        if len(data) == 0:
            return 0.0
        
        # Get unique values and their probabilities
        unique, counts = np.unique(data, return_counts=True)
        probabilities = counts / len(data)
        
        # Calculate entropy: -sum(p * log2(p))
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        
        return entropy
    
    def combine_datasets(self, dataset_types: list = None) -> pd.DataFrame:
        """
        Combine multiple datasets into one
        
        Args:
            dataset_types: List of dataset types to combine (or None for all)
        
        Returns:
            Combined DataFrame
        """
        
        if dataset_types is None:
            dataset_types = list(self.datasets.keys())
        
        dfs = []
        for dtype in dataset_types:
            if dtype not in self.datasets:
                self.load_dataset(dtype)
            dfs.append(self.datasets[dtype])
        
        combined = pd.concat(dfs, ignore_index=True)
        combined = combined.sort_values('Timestamp').reset_index(drop=True)
        
        print(f"Combined {len(dataset_types)} datasets:")
        print(f"  Total messages: {len(combined):,}")
        print(f"  Normal: {np.sum(combined['Label'] == 0):,}")
        print(f"  Attack: {np.sum(combined['Label'] == 1):,}\n")
        
        return combined
    
    def get_sample_messages(self, dataset_type: str = 'normal', 
                           n: int = 10) -> list:
        """Get sample CAN messages for testing"""
        
        if dataset_type not in self.datasets:
            self.load_dataset(dataset_type)
        
        df = self.datasets[dataset_type]
        sample = df.sample(min(n, len(df)))
        
        # Convert to can.Message objects
        import can
        messages = []
        
        for _, row in sample.iterrows():
            data = [int(row[f'Data{i}']) for i in range(8)]
            msg = can.Message(
                arbitration_id=int(row['CAN_ID']),
                data=data,
                is_extended_id=False
            )
            messages.append(msg)
        
        return messages


# Example usage
if __name__ == "__main__":
    # Initialize loader
    loader = HCRLDataset('/path/to/dataset')
    
    # Load datasets
    normal_df = loader.load_dataset('normal')
    dos_df = loader.load_dataset('dos')
    
    # Print statistics
    loader.print_statistics('normal')
    loader.print_statistics('dos')
    
    # Extract features for ML
    combined_df = loader.combine_datasets(['normal', 'dos'])
    X, y = loader.extract_features(combined_df, window_size=10)
    
    print(f"Ready for ML training:")
    print(f"  X shape: {X.shape}")
    print(f"  y shape: {y.shape}")
#!/usr/bin/env python3
"""
AI Model Training Pipeline
All training performed locally - NO external services

Usage:
    python ai-agent/train_models.py
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from unified_oss.fcaps.fault.ai_alarm_analysis import AIModelTrainer


def main():
    """Run the full AI model training pipeline"""
    
    print("=" * 60)
    print("UNIFIED OSS FRAMEWORK - AI MODEL TRAINING")
    print("=" * 60)
    print("Security: LOCAL ONLY - No external API calls")
    print("=" * 60)
    
    # Initialize trainer
    trainer = AIModelTrainer(
        training_data_path='./simulation_data/alarms/',
        models_output_path='./ai-agent/models/trained/'
    )
    
    # Run full training pipeline
    print("\nStarting training pipeline...")
    report = trainer.run_full_training_pipeline()
    
    # Print report
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    
    if report:
        for model_name, model_path in report.items():
            print(f"  {model_name}: {model_path}")
    else:
        print("  Note: Models require training data in simulation_data/alarms/")
    
    print("=" * 60 + "\n")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

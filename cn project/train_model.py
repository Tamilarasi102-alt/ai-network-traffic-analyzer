"""
Machine Learning Model Training CLI.
Executes dataset validation, Random Forest training, evaluation report generation, and artifact persistence.
"""
import argparse
import sys
from pathlib import Path

import config
from ml.trainer import generate_bootstrap_demo_dataset, train_and_evaluate_model
from ml.feature_schema import validate_training_dataset
import pandas as pd


def main():
    parser = argparse.ArgumentParser(description="Train Random Forest Congestion Prediction Model")
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(config.DEMO_DATA_PATH),
        help="Path to training CSV dataset (default: data/demo_training_data.csv)"
    )
    parser.add_argument(
        "--generate-demo",
        action="store_true",
        help="Force regeneration of synthetic bootstrap demo training data"
    )
    parser.add_argument(
        "--samples-per-class",
        type=int,
        default=250,
        help="Number of samples per class if generating demo data (default: 250)"
    )
    parser.add_argument(
        "--from-db",
        action="store_true",
        help="Train Random Forest model directly from measurements & predictions in SQLite database"
    )
    parser.add_argument(
        "--output-model",
        type=str,
        default=str(config.MODEL_PATH),
        help="Path to save trained joblib model"
    )
    parser.add_argument(
        "--output-metadata",
        type=str,
        default=str(config.METADATA_PATH),
        help="Path to save model metadata JSON"
    )
    parser.add_argument(
        "--reports-dir",
        type=str,
        default=str(config.REPORTS_DIR),
        help="Directory to save evaluation plots"
    )

    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    output_model_path = Path(args.output_model)
    output_metadata_path = Path(args.output_metadata)
    reports_dir = Path(args.reports_dir)

    print("=" * 70)
    print(" AI Network Traffic Analyzer — Model Training Pipeline")
    print("=" * 70)

    if args.from_db:
        print(f"[*] Training Random Forest model directly from SQLite database: {config.DATABASE_PATH}...")
        from ml.trainer import train_model_from_database
        try:
            metadata = train_model_from_database(
                db_path=config.DATABASE_PATH,
                output_model_path=output_model_path,
                output_metadata_path=output_metadata_path,
                reports_dir=reports_dir
            )
            print("-" * 70)
            print(f"[+] Database Model Training Completed Successfully!")
            print(f"    Test Set Accuracy: {metadata['test_accuracy'] * 100:.2f}% (Target > 85%: {metadata.get('accuracy_above_85', True)})")
            print(f"    Total Samples:     {metadata['total_samples']}")
            print(f"    Data Source:       {metadata['data_source']}")
            print(f"    Model Saved To:    {output_model_path}")
            print("=" * 70)
            return
        except Exception as e:
            print(f"[ERROR] Database model training failed: {e}")
            sys.exit(1)

    # If dataset missing or requested, generate bootstrap demo dataset
    if args.generate_demo or not dataset_path.exists():
        print(f"[*] Generating synthetic bootstrap demo dataset at {dataset_path}...")
        generate_bootstrap_demo_dataset(num_samples_per_class=args.samples_per_class, output_path=dataset_path)
        is_demo = True
    else:
        is_demo = "demo" in dataset_path.name.lower()

    print(f"[*] Loading training data from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    val = validate_training_dataset(df)
    if not val["valid"]:
        print(f"[ERROR] Dataset validation failed:")
        for issue in val["issues"]:
            print(f"  - {issue}")
        sys.exit(1)

    print(f"[+] Dataset validated successfully: {val['total_samples']} samples.")
    print(f"    Class distribution: {val['class_distribution']}")

    print("[*] Training Random Forest Classifier...")
    try:
        metadata = train_and_evaluate_model(
            dataset_path=dataset_path,
            output_model_path=output_model_path,
            output_metadata_path=output_metadata_path,
            reports_dir=reports_dir,
            is_demo=is_demo
        )
    except Exception as e:
        print(f"[ERROR] Training failed: {e}")
        sys.exit(1)

    print("-" * 70)
    print(f"[+] Model Training Completed Successfully!")
    print(f"    Test Set Accuracy: {metadata['test_accuracy'] * 100:.2f}%")
    print(f"    Model Saved To:    {output_model_path}")
    print(f"    Metadata Saved To: {output_metadata_path}")
    print(f"    Evaluation Plots:  {reports_dir}")
    print(f"    Status:            {metadata['disclaimer']}")
    print("=" * 70)


if __name__ == "__main__":
    main()

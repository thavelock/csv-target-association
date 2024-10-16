# CSV Target Association

## Usage

```shell
# Start the poetry environment
poetry shell
poetry install

# Verify you can now run the CLI
csv-target-association --help

# Optionally Set Up Environment Variables
export SNYK_TOKEN=<YOUR-SNYK-TOKEN> # Your Snyk API Token
export SNYK_ORG_ID=<SNYK-ORG-ID>    # Snyk Org ID to pull information from
```

## Commands
### `generate-csv`
This command will generate the contents of a CSV based on the Targets that are present in a Snyk Organization
```shell
# Generate CSV data for a given org
csv-target-association generate-csv --snyk-token=<SNYK_TOKEN> --org-id=<ORG_ID> --output-file=something.csv

# Generate CSV data for a given org (using env variables)
csv-target-association generate-csv --output-file=something.csv

# Generate CSV data for a given org only with Targets from a specific integration source
# e.g. github-enterprise, ecr, docker-hub
csv-target-association generate-csv --output-file=something.csv --source-types=ecr
```

### `apply-tags`
Applies tags based off of an input CSV file outlined in the following section
```shell
# Apply tags
csv-target-association apply-tags --csv-path=<PATH_TO_CSV>
```

### `clear-output`
Clears the the `/output` directory
```shell
csv-target-association clear-output
```

## CSV Input Format
The columns for the input CSV must be in the following format
```
SCM_ORG_ID, SCM_TARGET_NAME, SCM_TARGET_ID, CONTAINER_ORG_ID, CONTAINER_TARGET_NAME, CONTAINER_TARGET_ID
```
The output from the `generate-csv` command will output the following format
```
ORG_ID, TARGET_NAME, TARGET_ID
```
So, the output from the `generate-csv` command could be easily use to help construct the input CSV file for the `apply-tags` command
"""Primary logic for the CLI Tool
"""

import csv
import os

import typer
from rich import print
from typing_extensions import Annotated

from csv_target_association.lib import snyk

# ===== CONSTANTS =====

OUTPUT_DIR = "output"

# ===== GLOBALS =====

app = typer.Typer(add_completion=False)
state = {"verbose": False}

# ===== METHODS =====

@app.command()
def generate_csv(
    snyk_token:
        Annotated[
            str,
            typer.Option(
                help='Snyk API token',
                envvar='SNYK_TOKEN',
                default=...)],
    org_id:
        Annotated[
            str,
            typer.Option(
                help='Snyk API token',
                envvar='SNYK_ORG_ID',
                default=...)],
    output_file:
        Annotated[
            str,
            typer.Option(
                help='Output filename')] = 'output.csv',
    source_types:
        Annotated[
            str,
            typer.Option(
                help='Filter specific target source types, e.g. ecr, github-enterprise, etc.')] = ''):

    targets = snyk.get_all_targets_in_org(snyk_token=snyk_token, org_id=org_id, source_types=source_types)

    output_csv = ''

    if output_file.endswith('.csv'):
        output_csv = f'{OUTPUT_DIR}/{output_file}'
    else:
        output_csv = f'{OUTPUT_DIR}/{output_file}.csv'

    with open(output_csv, 'w') as csv_file:
        output_csv_writer = csv.writer(csv_file)
        for target in targets:
                output_csv_writer.writerow([org_id,target['attributes']['display_name'],target['id']])

@app.command()
def apply_tags(
    snyk_token:
        Annotated[
            str,
            typer.Option(
                help='Snyk API token',
                envvar='SNYK_TOKEN',
                default=...)],
    csv_path:
        Annotated[
            str,
            typer.Option(
                help='Path to input CSV file with format: SCM_ORG_ID, SCM_TARGET_NAME, SCM_TARGET_ID, CONTAINER_ORG_ID, CONTAINER_TARGET_NAME, CONTAINER_TARGET_ID',
                default=...)],
    dry_run:
        Annotated[
            bool,
            typer.Option(
                help='Print projects to be tagged without tagging')] = False,
    ):
    
    with open(csv_path) as csv_file:
        csv_reader = csv.reader(csv_file)

        for row in csv_reader:
            # SCM_ORG_ID, SCM_TARGET_NAME, SCM_TARGET_ID, CONTAINER_ORG_ID, CONTAINER_TARGET_NAME, CONTAINER_TARGET_ID

            if len(row) == 6:
                scm_org_id = row[0]
                scm_target_name = row[1]
                scm_target_id = row[2]
                container_org_id = row[3]
                container_target_name = row[4]
                container_target_id = row[5]

                scm_projects = snyk.get_all_projects_in_target(snyk_token=snyk_token,
                                                               org_id=scm_org_id,
                                                               target_id=scm_target_id)
                
                branch = scm_projects[0]['attributes']['target_reference']
                origin = scm_projects[0]['attributes']['origin']

                if origin == 'github-enterprise':
                    origin = 'github'

                container_projects = snyk.get_all_projects_in_target(snyk_token=snyk_token,
                                                                     org_id=container_org_id,
                                                                     target_id=container_target_id)

                component_tag = f'{origin}/{scm_target_name}@{branch}'

                for project in scm_projects:
                    print(f'Tagging project: {project['attributes']['name']}, with tag: {component_tag}')
                    if not dry_run:
                        snyk.apply_component_tag(snyk_token=snyk_token,
                                                 org_id=scm_org_id,
                                                 project_id=project['id'],
                                                 component_tag_value=component_tag)
                        
                for project in container_projects:
                    print(f'Tagging project: {project['attributes']['name']}, with tag: {component_tag}')
                    if not dry_run:
                        snyk.apply_component_tag(snyk_token=snyk_token,
                                                 org_id=container_org_id,
                                                 project_id=project['id'],
                                                 component_tag_value=component_tag)

@app.command()
def clear_output():
    files = os.listdir(OUTPUT_DIR)
    files.remove('.gitignore')

    for f in files:
        os.remove(f'{OUTPUT_DIR}/{f}')

@app.callback()
def main(verbose: bool = False):
    if verbose:
        state['verbose'] = True

def run():
    """Run the defined typer CLI App
    """
    app()
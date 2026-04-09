import click
from cli.commands import scan, info, test_connection


@click.group()
@click.version_option(version="1.0.0", prog_name="OWASP Scanner")
def app():
    pass


app.add_command(scan)
app.add_command(info)
app.add_command(test_connection)
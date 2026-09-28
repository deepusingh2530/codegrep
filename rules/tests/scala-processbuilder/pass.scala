class TaskRunner {
  def run(script: String) = {
    val exit = scriptRunner.execute(script)
    exit
  }
}

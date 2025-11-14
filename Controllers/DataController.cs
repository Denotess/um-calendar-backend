using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using NSwag.Annotations;
namespace UmCalendar.Controllers
{

    [Route("data")]
    [ApiController]
    [Authorize]
    [OpenApiTag("Data")]
    public class DataController : ControllerBase
    {
        private readonly string _calendarPath;
        public DataController(string calendarPath)
        {
            _calendarPath = calendarPath;
        }
        [HttpGet("names")]
        public IActionResult GetNames()
        {
            string[] icsFiles = Directory.GetFiles(_calendarPath, "*.ics");
            var names = icsFiles
                .Select(f => Path.GetFileNameWithoutExtension(f))
                .OrderBy(n => n)
                .ToArray();

            return Ok(names);

        }
        [HttpGet("cal/{name}")]
        public IActionResult GetCalendar(string name)
        {
            var filePath = Path.Combine(_calendarPath, name + ".ics");
            if (!System.IO.File.Exists(filePath))
            {
                return NotFound();
            }
            var fileContent = System.IO.File.ReadAllText(filePath);
            return Content(fileContent, "text/calendar; charset=utf-8");

        }


    }
}


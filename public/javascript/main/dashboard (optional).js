// This has no effect on the actual dashboard.ejs because it was made just to perfom testing (to verify the functionality) and that's it.

// So, don't get confused to see it, eh! :)


document.addEventListener('DOMContentLoaded', function () {

    const assignments = [
        {
            id: 1,
            title: "Math Homework",
            student: "John Doe",
            dueDate: "2023-10-01",
            status: "Not Started"
        },
    
        {
            id: 2,
            title: "Science Project",
            student: "Jane Smith",
            dueDate: "2023-10-05",
            status: "In Progress"
        },
    
        {
            id: 3,
            title: "History Essay",
            student: "Sam Wilson",
            dueDate: "2023-10-10",
            status: "Completed"
        }
    ];

    const assignmentsContainer = document.getElementById('assignments-container');

    assignments.forEach(assignment => {
        const card = document.createElement('div');
        card.className = 'col-md-4';

        card.innerHTML = `
            <div class="card mb-4 shadow-sm">

                <div class="card-body">
                    <h5 class="card-title">${assignment.title}</h5>
                    <p class="card-text">Student: ${assignment.student}</p>
                    <p class="card-text">Due Date: ${assignment.dueDate}</p>

                    <div class="card-status">
                        <span>Status: ${assignment.status}</span>
                        <input type="checkbox" class="status-checkbox" data-id="${assignment.id}" ${assignment.status === "In Progress" ? "checked" : ""}>
                    </div>
                </div>
    
            </div>
        `;
   
        assignmentsContainer.appendChild(card);
    });




    document.querySelectorAll('.status-checkbox').forEach(checkbox => {
        
        checkbox.addEventListener('change', function () {
        
            const assignmentId = this.getAttribute('data-id');
            const card = this.closest('.card');
            const statusSpan = card.querySelector('.card-status span');
         
            if(this.checked){
                statusSpan.textContent = 'Status: In Progress';
                
            } 
            
            else{
                statusSpan.textContent = 'Status: Not Started';
            }
        });
    });
});

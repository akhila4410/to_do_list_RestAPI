import uvicorn
from fastapi import FastAPI, HTTPException, Query, status
from pymongo import MongoClient
from pydantic import BaseModel

app = FastAPI()

# Connect Python with MongoDB
cl = MongoClient("mongodb+srv://akki712:4410@awsinstances.2sixhn0.mongodb.net/?retryWrites=true&w=majority&appName=awsinstance")
db = cl["to_do"]
collection = db["collection"]

class Task(BaseModel):
    Task: str
    Done: str

@app.get('/', response_class=RedirectResponse, include_in_schema=False)
async def docs():
    return RedirectResponse(url='/docs')

@app.get('/tasks/', response_model=list)
def get_all_tasks():
    tasks = list(db.collection.find({}, {"_id": 0}))
    return tasks

@app.post('/tasks/', response_model=dict)
def add_task(task: Task):
    db.collection.insert_one(task.dict())
    return {"message": "Task added successfully"}

@app.put('/tasks/{task_name}', response_model=dict)
def update_task(task_name: str, done: str):
    result = db.collection.update_one({"Task": task_name}, {"$set": {"Done": done}})
    if result.matched_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    return {"message": "Task updated successfully"}

@app.delete('/tasks/{task_name}', response_model=dict)
def delete_task(task_name: str):
    result = db.collection.delete_one({"Task": task_name})
    if result.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    return {"message": "Task deleted successfully"}

if __name__ == '__main__':
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)

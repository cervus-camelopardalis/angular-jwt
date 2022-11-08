import { Component, OnInit } from '@angular/core';

import { FormGroup } from '@angular/forms';
import { FormControl } from '@angular/forms';
import { Validators } from '@angular/forms';

@Component({
  selector: 'app-sign-up',
  templateUrl: './sign-up.component.html',
  styleUrls: ['./sign-up.component.scss']
})
export class SignUpComponent implements OnInit {

  hide = true;

  formSignUp = new FormGroup({
    "email": new FormControl("", Validators.required),
    "password": new FormControl("", Validators.required),
  });
    
  onSubmitSignUp() {
    console.log("Sign up: Reactive form submitted ✓");
    console.log(this.formSignUp.value);
  }

  constructor() { }

  ngOnInit(): void {
  }

}
